# A reopening of a type this tree does not own: R-3's one case, and the
# migration keeps it as Crystal beside the module.
struct Int32
  def liras : String
    "#{self} TRY"
  end

  # A reopening of somebody else's type stays Crystal in a sidecar (R-3),
  # and it names this tree's own types too: `Shop::Models::Item` moved
  # when the tree became modules, and a sidecar has no `using` line to
  # reach it through, so the new name is written here in full. It is
  # called from this file's own module, because a reopening's methods
  # travel as source and a consumer reading the artifact has not read it.
  def priced_like(item : Shop::Models::Item) : String
    "#{self}/#{item.price}"
  end
end

module Shop
  module Counter
    def self.priced(item : Shop::Models::Item) : String
      3.priced_like(item)
    end

    def self.report(count : Int32) : String
      count.liras
    end

    # A call on this module's *own* namespace: the wrapper becomes the
    # module, so `Shop::Counter.report` is `report` here - left qualified
    # it read as a name the module does not export, in a file nobody
    # wrote.
    def self.twice(count : Int32) : String
      "#{Shop::Counter.report(count)} x2"
    end
  end
end
