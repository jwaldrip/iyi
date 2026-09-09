require "./names"

module Shop
  include Names

  CURRENCY = "TRY"
  LIMIT    = 3

  # A name for a type, and an annotation a *consumer* applies: both are
  # part of a module's surface (R-2), so both take `pub` when the tree
  # becomes modules, and both travel in the artifact - the alias as what
  # it resolved to, the annotation as its name.
  alias Money = Int32

  annotation Priced; end

  def self.banner : String
    "#{Shop::Names::SHOP} in #{CURRENCY}"
  end
end
