# This module holds shared logic that doesn't really belong anywhere else in the
# gem.
module Docker::Util
  # http://www.tldp.org/LDP/GNU-Linux-Tools-Summary/html/x11655.htm#STANDARD-WILDCARDS
  GLOB_WILDCARDS = /[\?\*\[\{]/

  include Docker::Error

  module_function

  # Attaches to a HTTP stream
  #
  # @param block
  # @param msg_stack [Docker::Messages]
  # @param tty [boolean]
  def attach_for(block, msg_stack, tty = false)
    # If TTY is enabled expect raw data and append to stdout
    if tty
      attach_for_tty(block, msg_stack)
    else
      attach_for_multiplex(block, msg_stack)
    end
  end

  def attach_for_tty(block, msg_stack)
    messages = Docker::Messages.new
    lambda do |c,r,t|
      messages.stdout_messages << c
      messages.all_messages << c
      msg_stack.append(messages)

      block.call c if block
    end
  end

  def attach_for_multiplex(block, msg_stack)
    messages = Docker::Messages.new
    lambda do |c,r,t|
      messages = messages.decipher_messages(c)

      unless block.nil?
        messages.stdout_messages.each do |msg|
          block.call(:stdout, msg)
        end
        messages.stderr_messages.each do |msg|
          block.call(:stderr, msg)
        end
      end

      msg_stack.append(messages)
    end
  end

  def debug(msg)
    Docker.logger.debug(msg) if Docker.logger
  end

  def hijack_for(stdin, block, msg_stack, tty)
    attach_block = attach_for(block, msg_stack, tty)

    lambda do |socket|
      debug "hijack: hijacking the HTTP socket"
      threads = []

      debug "hijack: starting stdin copy thread"
      threads << Thread.start do
        debug "hijack: copying stdin => socket"
        IO.copy_stream stdin, socket

        debug "hijack: closing write end of hijacked socket"
        close_write(socket)
      end

      debug "hijack: starting hijacked socket read thread"
      threads << Thread.start do
        debug "hijack: reading from hijacked socket"

        begin
          while chunk = socket.readpartial(512)
            debug "hijack: got #{chunk.bytesize} bytes from hijacked socket"
            attach_block.call chunk, nil, nil
          end
        rescue EOFError
        end

        debug "hijack: killing stdin copy thread"
        threads.first.kill
      end

      threads.each(&:join)
    end
  end

  def close_write(socket)
    if socket.respond_to?(:close_write)
      socket.close_write
    elsif socket.respond_to?(:io)
      socket.io.close_write
    else
      raise IOError, 'Cannot close socket'
    end
  end

  def parse_json(body)
    MultiJson.load(body) unless body.nil? || body.empty? || (body == 'null')
  rescue MultiJson::ParseError => ex
    raise UnexpectedResponseError, ex.message
  end

  def parse_repo_tag(str)
    if match = str.match(/\A(.*):([^:]*)\z/)
      match.captures
    else
      [str, '']
    end
  end

  def fix_json(body)
    parse_json("[#{body.gsub(/}\s*{/, '},{')}]")
  end

  def create_tar(hash = {})
    output = StringIO.new
    Gem::Package::TarWriter.new(output) do |tar|
      hash.each do |file_name, file_details|
        permissions = file_details.is_a?(Hash) ? file_details[:permissions] : 0640
        tar.add_file(file_name, permissions) do |tar_file|
          content = file_details.is_a?(Hash) ? file_details[:content] : file_details
          tar_file.write(content)
        end
      end
    end
    output.tap(&:rewind).string
  end

  def create_dir_tar(directory)
    tempfile = create_temp_file
    directory += '/' unless directory.end_with?('/')

    create_relative_dir_tar(directory, tempfile)

    File.new(tempfile.path, 'r')
  end

  def create_relative_dir_tar(directory, output)
    Gem::Package::TarWriter.new(output) do |tar|
      files = glob_all_files(File.join(directory, "**/*"))
      remove_ignored_files!(directory, files)

      files.each do |prefixed_file_name|
        stat = File.stat(prefixed_file_name)
        next unless stat.file?

        unprefixed_file_name = prefixed_file_name[directory.length..-1]
        add_file_to_tar(
          tar, unprefixed_file_name, stat.mode, stat.size, stat.mtime
        ) do |tar_file|
          IO.copy_stream(File.open(prefixed_file_name, 'rb'), tar_file)
        end
      end
    end
  end

  def add_file_to_tar(tar, name, mode, size, mtime)
    tar.check_closed

    io = tar.instance_variable_get(:@io)

    name, prefix = tar.split_name(name)

    header = Gem::Package::TarHeader.new(:name => name, :mode => mode,
                                         :size => size, :prefix => prefix,
                                         :mtime => mtime).to_s

    io.write header
    os = Gem::Package::TarWriter::BoundedStream.new io, size

    yield os if block_given?

    min_padding = size - os.written
    io.write("\0" * min_padding)

    remainder = (512 - (size % 512)) % 512
    io.write("\0" * remainder)

    tar
  end

  def create_temp_file
    tempfile_name = Dir::Tmpname.create('out') {}
    File.open(tempfile_name, 'wb+')
  end

  def extract_id(body)
    body.lines.reverse_each do |line|
      if (id = line.match(/Successfully built ([a-f0-9]+)/)) && !id[1].empty?
        return id[1]
      end
    end
    raise UnexpectedResponseError, "Couldn't find id: #{body}"
  end

  # Convenience method to get the file hash corresponding to an array of
  # local paths.
  def file_hash_from_paths(local_paths)
    local_paths.each_with_object({}) do |local_path, file_hash|
      unless File.exist?(local_path)
        raise ArgumentError, "#{local_path} does not exist."
      end

      basename = File.basename(local_path)
      if File.directory?(local_path)
        tar = create_dir_tar(local_path)
        file_hash[basename] = {
          content: tar.read,
          permissions: filesystem_permissions(local_path)
        }
        tar.close
        FileUtils.rm(tar.path)
      else
        file_hash[basename] = {
          content: File.read(local_path, mode: 'rb'),
          permissions: filesystem_permissions(local_path)
        }
      end
    end
  end

  def filesystem_permissions(path)
    mode = sprintf("%o", File.stat(path).mode)
    mode[(mode.length - 3)...mode.length].to_i(8)
  end

  def build_auth_header(credentials)
    credentials = MultiJson.dump(credentials) if credentials.is_a?(Hash)
    encoded_creds = Base64.urlsafe_encode64(credentials)
    {
      'X-Registry-Auth' => encoded_creds
    }
  end

  def build_config_header(credentials)
    if credentials.is_a?(String)
      credentials = MultiJson.load(credentials, symbolize_keys: true)
    end

    header = MultiJson.dump(
      credentials[:serveraddress].to_s => {
        'username' => credentials[:username].to_s,
        'password' => credentials[:password].to_s,
        'email' => credentials[:email].to_s
      }
    )

    encoded_header = Base64.urlsafe_encode64(header)

    {
      'X-Registry-Config' => encoded_header
    }
  end

  def glob_all_files(pattern)
    Dir.glob(pattern, File::FNM_DOTMATCH) - ['..', '.']
  end

  def remove_ignored_files!(directory, files)
    ignore = File.join(directory, '.dockerignore')
    return unless files.include?(ignore)
    ignored_files(directory, ignore).each { |f| files.delete(f) }
  end

  def ignored_files(directory, ignore_file)
    patterns = File.read(ignore_file).split("\n").each(&:strip!)
    patterns.reject! { |p| p.empty? || p.start_with?('#') }
    patterns.map! { |p| File.join(directory, p) }
    patterns.map! { |p| File.directory?(p) ? "#{p}/**/*" : p }
    patterns.flat_map { |p| p =~ GLOB_WILDCARDS ? glob_all_files(p) : p }
  end

  def container_copy(container, source_path, dest_path, required: true)
    LOG.info "Copying #{source_path} to #{dest_path}... "

    tar = StringIO.new
    begin
      container.copy(source_path) do |chunk|
        tar.write(chunk)
      end
    rescue => e
      raise e if required
      puts "Not Found"
    end
    tar.rewind

    extended_headers = nil
    reader = Gem::Package::TarReader.new(tar)
    reader.each do |entry|
      # Using https://github.com/kr/tarutil/blob/master/untar.go as a template
      # Also check out https://go.googlesource.com/go/+/master/src/archive/tar/reader.go?autodive=0%2F%2F%2F
      case entry.header.typeflag
      when TarTypeFlag::TYPE_DIR
        merge_pax(entry, extended_headers)
        dest_name = calc_dest_name(source_path, dest_path, entry)
        create_directory(entry, dest_name)

      when TarTypeFlag::TYPE_REG, TarTypeFlag::TYPE_REG_A
        merge_pax(entry, extended_headers)
        dest_name = calc_dest_name(source_path, dest_path, entry)
        create_file(entry, dest_name)

      when TarTypeFlag::TYPE_LINK
        raise 'Unimplemented file type: Link'

      when TarTypeFlag::TYPE_SYMLINK
        merge_pax(entry, extended_headers)
        dest_name = calc_dest_name(source_path, dest_path, entry)
        create_symlink(entry, dest_name)

      when TarTypeFlag::TYPE_X_HEADER
        extended_headers = parse_pax(entry.read)
        next

      when TarTypeFlag::TYPE_CONT, TarTypeFlag::TYPE_X_GLOBAL_HEADER
        raise 'Unimplemented file type Cont/XGlobalHeader'

      when TarTypeFlag::TYPE_CHAR, TarTypeFlag::TYPE_BLOCK, TarTypeFlag::TYPE_FIFO
        raise 'Unimplemented file type: Char/Block/Fifo'

      else
        raise 'Unrecognized file type'

      end

      # If we got here we should be done with any extended headers
      extended_headers = nil
    end
  end

  # NOTE: These methods are most likely not complete
  def parse_pax(content)
    extended_headers = {}
    key, value = parse_pax_record(content)
    extended_headers[key] = value
    extended_headers
  end

  def parse_pax_record(content)
    # Check https://golang.org/src/archive/tar/strconv.go
    size, keyvalue = content&.split(' ', 2)
    key, value = keyvalue&.split('=', 2)
    [key, value]
  end

  def calc_dest_name(source_path, dest_path, entry)
    dest_path = dest_path.to_s.strip.chomp('/')
    return dest_path unless File.directory?(dest_path)

    source_path = source_path.to_s.strip.chomp('/')
    full_name = entry.full_name.to_s.strip
    full_name = full_name.sub(%r{^#{source_path}/}, '')
    "#{dest_path.chomp('/')}/#{full_name}"
  end

  def create_directory(entry, dest_name)
    FileUtils.mkdir_p(dest_name)
  end

  def create_file(entry, dest_name)
    FileUtils.mkdir_p(File.dirname(dest_name))
    IO.write(dest_name, entry.read)
  end

  def create_symlink(entry, dest_name)
    FileUtils.cd(File.dirname(dest_name)) {
      FileUtils.mkdir_p(File.dirname(entry.header.linkname))
      FileUtils.symlink(entry.header.linkname, File.basename(dest_name))
    }
  end

  def merge_pax(entry, extended_headers)
    # Reference: https://go.googlesource.com/go/+/master/src/archive/tar/reader.go?autodive=0%2F%2F%2F
    return unless extended_headers

    extended_headers.each do |k, v|
      case k
      when PaxHeader::PAX_PATH
        entry.header.instance_variable_set(:@name, v)

      when PaxHeader::PAX_LINKPATH
        entry.header.instance_variable_set(:@linkname, v)

      when PaxHeader::PAX_UNAME
        entry.header.instance_variable_set(:@uname, v)

      when PaxHeader::PAX_GNAME
        entry.header.instance_variable_set(:@gname, v)

      when PaxHeader::PAX_UID
        entry.header.instance_variable_set(:@uid, v)

      when PaxHeader::PAX_GID
        entry.header.instance_variable_set(:@gid, v)

      when PaxHeader::PAX_ATIME
        entry.header.instance_variable_set(:@atime, v)

      when PaxHeader::PAX_MTIME
        entry.header.instance_variable_set(:@mtime, v)

      when PaxHeader::PAX_CTIME
        entry.header.instance_variable_set(:@ctime, v)

      when PaxHeader::PAX_SIZE
        entry.header.instance_variable_set(:@size, v)

      else
        raise "unsupported header #{k}"

      end
    end
  end

  # From https://golang.org/src/archive/tar/common.go?s=5701:5766
  module TarTypeFlag
    TYPE_REG             = '0'    # regular file
    TYPE_REG_A           = '\x00' # regular file
    TYPE_LINK            = '1'    # hard link
    TYPE_SYMLINK         = '2'    # symbolic link
    TYPE_CHAR            = '3'    # character device node
    TYPE_BLOCK           = '4'    # block device node
    TYPE_DIR             = '5'    # directory
    TYPE_FIFO            = '6'    # fifo node
    TYPE_CONT            = '7'    # reserved
    TYPE_X_HEADER        = 'x'    # extended header
    TYPE_X_GLOBAL_HEADER = 'g'    # global extended header
    TYPE_GNU_LONG_NAME   = 'L'    # Next file has a long name
    TYPE_GNU_LONG_LINK   = 'K'    # Next file symlinks to a file w/ a long name
    TYPE_GNU_SPARSE      = 'S'    # sparse file
  end

  module PaxHeader
    PAX_ATIME   = "atime"
    PAX_CHARSET = "charset"
    PAX_COMMENT = "comment"
    PAX_CTIME   = "ctime" # please note that ctime is not a valid pax header.
    PAX_GID     = "gid"
    PAX_GNAME   = "gname"
    PAX_LINKPATH= "linkpath"
    PAX_MTIME   = "mtime"
    PAX_PATH    = "path"
    PAX_SIZE    = "size"
    PAX_UID     = "uid"
    PAX_UNAME   = "uname"
    PAX_XATTR   = "SCHILY.xattr."
    PAX_NONE    = ""
  end

end
