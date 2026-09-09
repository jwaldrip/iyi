module Shop::Names
  SHOP = "corner shop"

  def self.title(what : String) : String
    "#{SHOP}: #{slug(what)}"
  end

  # A regex literal, which iyi refuses only where the program has no
  # runtime `Regex`: this tree is compiled against Crystal's library, where
  # the class behind the literal lives (SPEC.md III.10). The constant it
  # expands to travels in this module's artifact, which is what the
  # artifact steps below check.
  def self.slug(what : String) : String
    what.gsub(/[^a-z0-9]+/i, "-").strip('-')
  end
end
