require "json"
require "./cart"

module Shop::Models
  struct Item
    include JSON::Serializable

    getter name : String
    getter price : Int32

    def initialize(@name : String, @price : Int32)
    end

    # A cycle: an item knows which cart holds it, and a cart holds items.
    def in?(cart : Cart) : Bool
      cart.items.any? { |item| item.name == name }
    end

    def label : String
      Shop::Names.title(name)
    end
  end
end
