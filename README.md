# Amberletters

Amberletters is a console automation framework, similar to the classic
utility Expect. You give it a command to execute, and tell it which outputs
or events to expect and how to respond to them.

Thanks to https://github.com/avdi/greenletters for the start.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'amberletters'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install amberletters

## Usage

```ruby
require 'amberletters'

adv = Amberletters::Process.new("adventure", :transcript => $stdout)

# Install a handler which may be triggered at any time
adv.on(:output, /welcome to adventure/i) do |process, match_data|
  adv << "no\n"
end

puts "Starting adventure..."
adv.start!

# Wait for the specified pattern before proceeding
adv.wait_for(:output, /you are standing at the end of a road/i)
adv << "east\n"
adv.wait_for(:output, /inside a building/i)
adv << "quit\n"
adv.wait_for(:output, /really want to quit/i)
adv << "yes\n"
adv.wait_for(:exit)
puts "Adventure has exited."

```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/timgaleckas/amberletters. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Amberletters project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/timgaleckas/amberletters/blob/master/CODE_OF_CONDUCT.md).
