require "./models/item"

# A file name is not a module name: this one becomes `shop/price_list`,
# because `module shop/price-list` parses as a subtraction.
module Shop
  module PriceList
    # A chain that ends in `.not_nil!` on a line of its own: the receiver
    # is on the lines above, so the narrowing has to be one that composes
    # (III.1.7a).
    def self.dearest(items : Array(Shop::Models::Item)) : Shop::Models::Item
      items
        .sort_by(&.price)
        .last?
        .not_nil!
    end
  end
end
