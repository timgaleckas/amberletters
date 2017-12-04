require 'forwardable'
require 'logger'
require 'pty'
require 'rbconfig'
require 'stringio'
require 'strscan'

require "amberletters/version"

module Amberletters
  SystemError  = Class.new(RuntimeError)
  TimeoutError = Class.new(SystemError)
  ClientError  = Class.new(RuntimeError)
  StateError   = Class.new(ClientError)

  # This class offers a pass-through << operator and saves the most recent 256
  # bytes which have passed through.
  class TranscriptHistoryBuffer
    attr_reader :buffer

    def initialize(transcript)
      @buffer     = String.new
      @transcript = transcript
    end

    def <<(output)
      @buffer     << output
      @transcript << output
      length = [@buffer.length, 512].min
      @buffer = @buffer[-length, length]
      self
    end
  end

  class Trigger
    attr_accessor :exclusive
    attr_accessor :interruption
    attr_accessor :logger
    attr_accessor :time_to_live
    attr_reader   :options

    alias_method :exclusive?, :exclusive

    def initialize(options={}, &block)
      @block        = block || lambda{|*|}
      @exclusive    = options.fetch(:exclusive) { false }
      @logger       = ::Logger.new($stdout)
      @interruption = :none
      @options      = options
    end

    def call(process)
      @block.call(self, process)
      true
    end
  end

  class OutputTrigger < Trigger
    def initialize(pattern=//, options={}, &block)
      super(options, &block)
      options[:operation] ||= :all
      @pattern = pattern
    end

    def to_s
      "output matching #{@pattern.inspect}"
    end

    def call(process)
      case @pattern
      when Array then match_multiple(process)
      else match_one(process)
      end
    end

    def match_one(process)
      scanner = process.output_buffer

      @logger.debug "matching #{@pattern.inspect} against #{scanner.rest.inspect}"
      if scanner.scan_until(@pattern)
        @logger.debug "matched #{@pattern.inspect}"
        @block.call(self, process, scanner)
        true
      else
        false
      end
    end

    def match_multiple(process)
      op = options[:operation]
      raise "Invalid operation #{op.inspect}" unless [:any, :all].include?(op)

      scanner = process.output_buffer

      @logger.debug "matching #{op} of multiple patterns against #{scanner.rest.inspect}"
      starting_pos = scanner.pos
      ending_pos   = starting_pos
      result = @pattern.send("#{op}?") {|pattern|
        scanner.pos = starting_pos
        if (char_count = scanner.skip_until(pattern))
          ending_pos = [ending_pos, starting_pos + char_count].max
        end
      }
      if result
        scanner.pos = ending_pos
        true
      else
        scanner.pos = starting_pos
        false
      end
    end
  end

  class BytesTrigger < Trigger
    attr_reader :num_bytes

    def initialize(num_bytes, options={}, &block)
      super(options, &block)
      @num_bytes = num_bytes
    end

    def to_s
      "#{num_bytes} bytes of output"
    end

    def call(process)
      @logger.debug "checking if #{num_bytes} byes have been received"
      scanner = process.output_buffer

      if scanner.rest_size >= num_bytes
        @block.call(self, process, scanner)
        scanner.pos += num_bytes
        true
      else
        false
      end
    end
  end

  class TimeoutTrigger < Trigger
    attr_reader :expiration_time

    def initialize(expiration_time=Time.now+1.0, options={}, &block)
      super(options, &block)
      @expiration_time = case expiration_time
                         when Time then expiration_time
                         when Numeric then Time.now + expiration_time
                         end
    end

    def to_s
      "timeout at #{expiration_time}"
    end

    def call(process)
      if process.time >= expiration_time
        @block.call(self, process, process.blocker)
        true
      else
        false
      end
    end
  end

  class ExitTrigger < Trigger
    attr_reader :exitstatus

    def initialize(exitstatus=0, options={}, &block)
      super(options, &block)
      @exitstatus = exitstatus
    end

    def call(process)
      if process.status && exitstatus === process.status.exitstatus
        @block.call(self, process, process.status)
        true
      else
        false
      end
    end

    def to_s
      "exit with status #{exitstatus}"
    end
  end

  class UnsatisfiedTrigger < Trigger
    def to_s
      "unsatisfied wait"
    end

    def call(process)
      @block.call(self, process)
      true
    end
  end

  class Process
    END_MARKER              = '__AMBERLETTERS_PROCESS_ENDED__'
    DEFAULT_LOG_LEVEL       = ::Logger::WARN
    DEFAULT_TIMEOUT         = 1.0

    # Shamelessly stolen from Rake
    RUBY_EXT =
      ((RbConfig::CONFIG['ruby_install_name'] =~ /\.(com|cmd|exe|bat|rb|sh)$/) ?
      "" :
        RbConfig::CONFIG['EXEEXT'])
    RUBY       = File.join(
      RbConfig::CONFIG['bindir'],
      RbConfig::CONFIG['ruby_install_name'] + RUBY_EXT).
      sub(/.*\s.*/m, '"\&"')

    extend Forwardable

    attr_accessor :blocker       # The Trigger currently being waited for, if any
    attr_accessor :timeout       # Default timeout for any trigger
    attr_reader   :command       # Command to run in a subshell
    attr_reader   :cwd           # Working directory of command
    attr_reader   :input_buffer  # Input waiting to be written to process
    attr_reader   :output_buffer # Combined output ready to be read from process
    attr_reader   :status        # :not_started -> :running -> :ended -> :exited

    def_delegators :input_buffer, :puts, :write, :print, :printf, :<<
    def_delegators :blocker, :interruption, :interruption=

    def initialize(*args)
      options         = args.last.is_a?(Hash) ? args.pop : {}

      @blocker        = nil
      @command        = args
      @cwd            = options.fetch(:cwd) {Dir.pwd}
      @env            = options.fetch(:env) {{}}
      @input_buffer   = StringIO.new
      @output_buffer  = StringScanner.new("")
      @state          = :not_started
      @timeout        = options.fetch(:timeout) { DEFAULT_TIMEOUT }
      @triggers       = []

      @logger         = options.fetch(:logger) do
        l = ::Logger.new($stdout)
        l.level = DEFAULT_LOG_LEVEL
        l
      end

      @transcript    = options.fetch(:transcript) do
        t = Object.new
        def t.<<(*)
          # NOOP
        end
        t
      end
      @history        = TranscriptHistoryBuffer.new(@transcript)

      ObjectSpace.define_finalizer(self) do
        kill!
      end
    end

    def start!
      raise StateError, "Already started!" unless not_started?

      @logger.debug "installing end marker handler for #{END_MARKER}"
      prepend_trigger(:output, /#{END_MARKER}/, :exclusive => false) do |process, data|
        unless ended?
          @logger.debug "end marker found"
          @state = :ended
          @logger.debug "acknowledging end marker"
          self.puts
        end
      end

      handle_child_exit do
        @logger.debug "executing #{command.join(' ')}"
        @output, @input, @pid = PTY.spawn(*wrapped_command)
        @state = :running
        @logger.debug "spawned pid #{@pid}; input: #{@input.inspect}; output: #{@output.inspect}"
      end
    end

    def on(event, *args, &block)
      add_nonblocking_trigger(event, *args, &block)
    end

    def wait_for(event, *args, &block)
      raise "Already waiting for #{blocker}" if blocker
      t = add_blocking_trigger(event, *args, &block)
      @logger.debug "Entering wait cycle for #{event}"
      process_events
    rescue
      unblock!
      @triggers.delete(t)
      raise
    end

    def remove_trigger(t)
      @triggers.delete(t)
      @logger.debug "removed trigger on #{t}"
      t
    end

    def kill!(signal="TERM")
      @logger.info "Killing process #{@pid}"
      ::Process.kill(signal, @pid)
      @input.close
      @output.close
      ::Process.waitpid2(@pid)
    end

    def blocked?
      @blocker
    end

    def running?
      @state == :running
    end

    def not_started?
      @state == :not_started
    end

    def exited?
      @state == :exited
    end

    # Have we seen the end marker yet?
    def ended?
      @state == :ended
    end

    def time
      Time.now
    end

    def to_s
      "Process<pid: #{pid}; in: #{input.inspect}; out: #{output.inspect}>"
    end

    private

    def add_nonblocking_trigger(event, *args, &block)
      t = add_trigger(event, *args, &block)
      catchup_trigger!(t)
      t
    end

    def add_trigger(event, *args, &block)
      t = build_trigger(event, *args, &block)
      @triggers << t
      @logger.debug "added trigger on #{t}"
      t
    end

    def prepend_trigger(event, *args, &block)
      t = build_trigger(event, *args, &block)
      @triggers.unshift(t)
      @logger.debug "prepended trigger on #{t}"
      t
    end

    def add_blocking_trigger(event, *args, &block)
      t = add_trigger(event, *args, &block)
      t.time_to_live = 1
      @logger.debug "waiting for #{t}"
      self.blocker = t
      catchup_trigger!(t)
      t
    end

    def wrapped_command
      [RUBY,
        '-C', cwd,
        '-e', "system(*#{command.inspect})",
        '-e', "puts(#{END_MARKER.inspect})",
        '-e', "gets",
        '-e', "exit $?.exitstatus"
      ]
    end

    def build_trigger(event, *args, &block)
      klass = trigger_class_for_event(event)
      t = klass.new(*args, &block)
      t.logger = @logger if @logger
      t
    end

    def trigger_class_for_event(event)
      ::Amberletters.const_get("#{event.to_s.capitalize}Trigger")
    end

    def process_events
      raise StateError, "Process not started!" if not_started?
      while blocked?
        handle_child_exit do
          input_handles  = input_buffer.string.empty? ? [] : [@input]
          output_handles = [@output]
          timeout        = shortest_timeout
          @logger.debug "select() on #{[output_handles, input_handles, nil, timeout].inspect}"

          ready_handles = IO.select(
            output_handles, input_handles, nil, timeout)

          if ready_handles.nil?
            process_timeout
          else
            ready_outputs, ready_inputs = *ready_handles
            @logger.debug "processing channels #{ready_handles.inspect}"
            ready_outputs.each{|handle| process_output(handle)}
            ready_inputs.each{|handle| process_input(handle)}
          end
        end
      end
    end

    def process_input(handle)
      @logger.debug "input ready #{handle.inspect}"
      handle.write(input_buffer.string)
      @logger.debug format_for_log(input_buffer.string)
      @logger.debug "wrote #{input_buffer.string.size} bytes"
      input_buffer.string = ""
    end

    def process_output(handle)
      unless handle.eof?
        @logger.debug "output ready #{handle.inspect}"
        data = handle.readpartial(1024)
        output_buffer << data
        @history << data
        @logger.debug format_for_log(data)
        @logger.debug "read #{data.size} bytes"
        handle_triggers(:bytes)
        handle_triggers(:output)
      end
    end

    def collect_remaining_output
      @logger.debug "collecting remaining output"
      while data = (@output && !@output.eof? && @output.read_nonblock(1024))
        output_buffer << data
        @logger.debug "read #{data.size} bytes"
      end
    end

    def process_timeout
      if handle_triggers(:timeout)
        @logger.debug "timeout"
        process_interruption(:timeout)
      end
    end

    def handle_exit(status)
      unless exited?
        @logger.debug "handling exit of process #{@pid}"
        @state  = :exited
        @status = status
        handle_triggers(:exit)
        process_interruption(status.exitstatus == 0 ? :exit : :abnormal_exit)
      end
    end

    def handle_triggers(event)
      klass = trigger_class_for_event(event)
      matches = 0
      @triggers.grep(klass).each do |t|
        @logger.debug "checking #{event} against #{t}"
        check_trigger(t) do
          matches += 1
          break if t.exclusive?
        end
      end
      matches > 0
    end

    def check_trigger(trigger)
      if trigger.call(self) # match
        @logger.debug "match trigger #{trigger}"
        unblock!  if blocker.equal?(trigger)

        if trigger.time_to_live
          if trigger.time_to_live > 1
            trigger.time_to_live -= 1
            @logger.debug "trigger ttl reduced to #{trigger.time_to_live}"
          else
            @triggers.delete(trigger)
            @logger.debug "trigger removed"
          end
        end

        yield if block_given?
      else
        @logger.debug "no match"
      end
    end

    def unblock!
      @logger.debug "unblocked"
      @triggers.delete(@blocker)
      @blocker = nil
    end

    def handle_child_exit
      handle_eio do
        yield
      end
      _, status = ::Process.waitpid2(@pid, ::Process::WNOHANG)
      if status
        @logger.debug "Pid <#{@pid}> exited"
        collect_remaining_output
        handle_exit(status)
      end
    end

    def handle_eio
      yield
    rescue Errno::EIO => error
      @logger.debug "Errno::EIO caught. Waiting for child to exit."
      Process.waitpid2(@pid)
    end

    def flush_triggers!(kind)
      @logger.debug "flushing triggers matching #{kind}"
      @triggers.delete_if{|t| kind === t}
    end

    def process_interruption(reason)
      if blocked?
        self.interruption = reason
        unless handle_triggers(:unsatisfied)
          raise SystemError,
                "Interrupted (#{reason}) while waiting for #{blocker}.\n" \
                "Recent activity:\n" +
                @history.buffer + "\n" + ("-" * 60) + "\n"
        end
        unblock!
      end
    end

    def catchup_trigger!(trigger)
      @logger.debug "Catching up trigger #{trigger}"
      check_trigger(trigger)
    end

    def format_for_log(text)
      "\n" + text.split("\n").map{|l| ">> #{l}"}.join("\n")
    end

    def shortest_timeout
      [@triggers.grep(TimeoutTrigger).map{|t| t.expiration_time - Time.now }.min || @timeout, 0].max
    end
  end
end
