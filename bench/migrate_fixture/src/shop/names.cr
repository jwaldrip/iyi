module Shop::Names
  SHOP = "corner shop"

  def self.title(what : String) : String
    "#{SHOP}: #{what}"
  end
end
