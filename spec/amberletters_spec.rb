RSpec.describe Amberletters do
  let(:log_file) { '/dev/null' }

  let(:logger) do
    l = Logger.new(log_file)
    l.level = 0
    l
  end

  it "has a version number" do
    expect(Amberletters::VERSION).not_to be nil
  end

  it "should handle a process that exits immediately" do
    p = Amberletters::Process.new("echo hello")
    p.start!
    p.wait_for(:output, /hello/)
    p.wait_for(:exit)
  end

  it "should handle an error exit status" do
    p = Amberletters::Process.new("exit -1", logger: logger)
    p.start!
    p.wait_for(:exit, 255)
  end

  it "should report error and context when exiting prematurely" do
    p = Amberletters::Process.new("bash -c 'echo ___some_output___; exit 0'", logger: logger)
    p.start!
    expect{ p.wait_for(:output, /2/) }.to raise_error(/exit.*while waiting.*___some_output___/m)
  end

  it "should match based on bytes" do
    p = Amberletters::Process.new("bash -c 'echo -n #{'0' * 2048}'", logger: logger)
    p.start!
    p.wait_for(:bytes, 1024) do |process, trigger, scanner|
      expect(scanner.rest_size).to be >= 1024
    end
    p.wait_for(:bytes, 1024) do |process, trigger, scanner|
      expect(scanner.rest_size).to be >= 1024
      expect(scanner.string.size).to be >= 2048
    end
  end

  it "should be able to be killed" do
    p = Amberletters::Process.new("bash -c 'while true; do echo 0; done'", logger: logger)
    p.start!
    p.kill!
  end

  it "should be able to have a timeout per wait_for" do
    g = Amberletters::Process.new(<<-CMD, timeout: 600)
      bash -c "
sleep 1
echo 1
sleep 1
echo 2
sleep 1
echo 3
sleep 1
echo 4
sleep 1
echo 5
sleep 1
echo 6
sleep 1
echo 7
sleep 1
echo 8
sleep 1
echo 9
sleep 1
echo 10
"
    CMD
    g.start!

    timeout = g.on(:timeout, 1) do |trigger, process|
      process.remove_trigger(trigger)
      raise 'timeout'
    end

    expect{ g.wait_for(:output, /2/) }.to raise_error('timeout')

    g.wait_for(:output, /4/)

    timeout = g.on(:timeout, 3) do |trigger, process|
      process.remove_trigger(trigger)
      raise 'timeout'
    end

    g.wait_for(:output, /5/) do |trigger, process, match_data|
      process.remove_trigger(timeout)
      expect(match_data[0]).to eq("5")
    end

    expect{ g.wait_for(:output, /10/) }.to_not raise_error
  end
end
