# `shards install` writes other projects' source into a `lib/` beside the
# manifest. It is not this tree's to migrate: `iyi migrate .` used to read
# it and merge it into the project's own modules.
module Pretend
  VERSION = "0.1.0"

  def self.hello : String
    "not this tree's"
  end
end
