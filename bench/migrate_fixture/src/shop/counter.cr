# A reopening of a type this tree does not own: R-3's one case, and the
# migration keeps it as Crystal beside the module.
struct Int32
  def liras : String
    "#{self} TRY"
  end
end

module Shop
  module Counter
    def self.report(count : Int32) : String
      count.liras
    end
  end
end
