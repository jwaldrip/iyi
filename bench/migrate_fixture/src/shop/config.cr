require "./names"

module Shop
  include Names

  CURRENCY = "TRY"
  LIMIT    = 3

  def self.banner : String
    "#{Shop::Names::SHOP} in #{CURRENCY}"
  end
end
