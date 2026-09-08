require "./item"

module Shop::Models
  class Cart
    getter items : Array(Item)

    def initialize
      @items = [] of Item
    end

    def add(item : Item) : Int32
      items << item
      items.size
    end

    def total : Int32
      items.sum(&.price)
    end

    # `!` is III.1.7a's, and the migration rewrites this one.
    def dearest : Item
      items.max_by?(&.price).not_nil!
    end

    def cheapest_first : Array(Item)
      items.sort_by!(&.price)
    end
  end
end
