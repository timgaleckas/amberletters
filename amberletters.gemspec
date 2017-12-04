
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "amberletters/version"

Gem::Specification.new do |spec|
  spec.name          = "amberletters"
  spec.version       = Amberletters::VERSION
  spec.authors       = ["Tim Galeckas"]
  spec.email         = ["tim@galeckas.com"]

  spec.summary       = %q{A Ruby console automation framework a la Expect}
  spec.description   = %q{
    Amberletters is a console automation framework, similar to the classic
    utility Expect. You give it a command to execute, and tell it which outputs
    or events to expect and how to respond to them.
  }
  spec.homepage      = "https://github.com/timgaleckas/amberletters"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["allowed_push_host"] = "https://rubygems.org"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "pry"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
