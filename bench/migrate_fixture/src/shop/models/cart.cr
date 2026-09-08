require "./item"

module Shop::Models
  class Cart
    getter items : Array(Item)
    # `getter!` is `not_nil!` written by a macro: the reader raises where
    # nil. `!` is III.1.7a's, so a migration writes the raise where a
    # reader can see it and keeps the question the macro also answered.
    getter! note : String | Nil

    def initialize
      @items = [] of Item
      @note = "keep the receipt"
    end

    def add(item : Item) : Int32
      items << item
      items.size
    end

    # `!` is III.1.7a's, and which rewrite a bang gets depends on whose
    # method it is: `uniq!` is Crystal's in-place member and the copy has
    # to go back where the mutation was, `tidy!` is this tree's own and
    # loses its bang along with its definition. Textually they are the
    # same call, so the compiler is asked (SPEC.md III.6).
    def tidy! : Int32
      @items.uniq!
      items.size
    end

    def total : Int32
      items.sum(&.price)
    end

    # `!` is III.1.7a's, and the migration rewrites this one.
    def dearest : Item
      items.max_by?(&.price).not_nil!
    end

    # Untyped, the way Crystal lets it be: `--annotate` writes what the
    # calls said, and R-2 is satisfied without a person guessing.
    def holds?(item)
      items.any? { |held| held.name == item.name }
    end

    def cheapest_first : Array(Item)
      items.sort_by!(&.price)
    end
  end
end
