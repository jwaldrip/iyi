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

    # `private class` is file-private in the other language, and a def is
    # typed where it is written (III.1) by standing a probe up outside its
    # type - which cannot name a private one. Every def of a private class
    # nested in an exported one was refused until the probe learned that,
    # and nothing calls this one, because the probe does not need a call.
    private class Tally
      def zero : Int32
        0
      end
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
