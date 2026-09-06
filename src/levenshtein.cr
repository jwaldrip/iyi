# Levenshtein distance methods.
#
# NOTE: To use `Levenshtein`, you must explicitly import it with `require "levenshtein"`
module Levenshtein
  # Computes the [levenshtein distance](http://en.wikipedia.org/wiki/Levenshtein_distance) of two strings.
  #
  # ```
  # require "levenshtein"
  #
  # Levenshtein.distance("algorithm", "altruistic") # => 6
  # Levenshtein.distance("hello", "hallo")          # => 1
  # Levenshtein.distance("こんにちは", "こんちは")           # => 1
  # Levenshtein.distance("hey", "hey")              # => 0
  # ```
  def self.distance(string1 : String, string2 : String) : Int32
    return 0 if string1 == string2

    s_size = string1.size
    t_size = string2.size

    return t_size if s_size == 0
    return s_size if t_size == 0

    # This is to allocate less memory
    if t_size > s_size
      string1, string2 = string2, string1
      t_size, s_size = s_size, t_size
    end

    costs = Slice(Int32).new(t_size + 1) { |i| i }
    last_cost = 0

    if string1.single_byte_optimizable? && string2.single_byte_optimizable?
      s = string1.to_unsafe
      t = string2.to_unsafe

      s_size.times do |i|
        last_cost = i + 1

        t_size.times do |j|
          sub_cost = s[i] == t[j] ? 0 : 1
          cost = Math.min(Math.min(last_cost + 1, costs[j + 1] + 1), costs[j] + sub_cost)
          costs[j] = last_cost
          last_cost = cost
        end
        costs[t_size] = last_cost
      end

      last_cost
    else
      reader = Char::Reader.new(string1)

      # Use an array instead of a reader to decode the second string only once
      chars = string2.chars

      reader.each_with_index do |char1, i|
        last_cost = i + 1

        chars.each_with_index do |char2, j|
          sub_cost = char1 == char2 ? 0 : 1
          cost = Math.min(Math.min(last_cost + 1, costs[j + 1] + 1), costs[j] + sub_cost)
          costs[j] = last_cost
          last_cost = cost
        end
        costs[t_size] = last_cost
      end

      last_cost
    end
  end

  # Finds the closest string to a given string amongst many strings.
  #
  # ```
  # require "levenshtein"
  #
  # finder = Levenshtein::Finder.new "hallo"
  # finder.test "hay"
  # finder.test "hall"
  # finder.test "hallo world"
  #
  # finder.best_match # => "hall"
  # ```
  # iyi: the optimal string alignment distance - Levenshtein with an
  # adjacent transposition as one edit. `cuont` for `count` is two
  # edits by the classic measure and one by this one, and the compiler's
  # finder judges "did you mean" by a tolerance of a fifth of the name,
  # which is one edit for a name under ten characters: the commonest
  # typo was the one it never suggested. Two full rows kept rather than
  # one, since the transposition looks two rows back.
  def self.osa_distance(string1 : String, string2 : String) : Int32
    return 0 if string1 == string2
    a = string1.chars
    b = string2.chars
    return b.size if a.empty?
    return a.size if b.empty?
    width = b.size + 1
    two_back = Array(Int32).new(width, 0)
    previous = Array(Int32).new(width) { |j| j }
    current = Array(Int32).new(width, 0)
    a.each_with_index do |char1, i|
      current[0] = i + 1
      b.each_with_index do |char2, j|
        cost = char1 == char2 ? 0 : 1
        best = Math.min(Math.min(previous[j + 1] + 1, current[j] + 1), previous[j] + cost)
        if i > 0 && j > 0 && char1 == b[j - 1] && a[i - 1] == char2
          best = Math.min(best, two_back[j - 1] + 1)
        end
        current[j + 1] = best
      end
      two_back, previous, current = previous, current, two_back
    end
    previous[b.size]
  end

  class Finder
    # :nodoc:
    record Entry,
      value : String,
      distance : Int32

    @tolerance : Int32

    def initialize(@target : String, tolerance : Int? = nil)
      @tolerance = tolerance || (target.size / 5.0).ceil.to_i
    end

    def test(name : String, value : String = name)
      distance = Levenshtein.osa_distance(@target, name)
      if distance <= @tolerance
        if best_entry = @best_entry
          if distance < best_entry.distance
            @best_entry = Entry.new(value, distance)
          end
        else
          @best_entry = Entry.new(value, distance)
        end
      end
    end

    def best_match : String?
      @best_entry.try &.value
    end

    def self.find(name, tolerance = nil, &)
      sn = new name, tolerance
      yield sn
      sn.best_match
    end

    def self.find(name, all_names, tolerance = nil) : String?
      find(name, tolerance) do |similar|
        all_names.each do |a_name|
          similar.test(a_name)
        end
      end
    end
  end

  # Finds the best match for *name* among strings added within the given block.
  # *tolerance* can be used to set maximum Levenshtein distance allowed.
  #
  # ```
  # require "levenshtein"
  #
  # best_match = Levenshtein.find("hello") do |l|
  #   l.test "hulk"
  #   l.test "holk"
  #   l.test "halka"
  #   l.test "ello"
  # end
  # best_match # => "ello"
  # ```
  def self.find(name, tolerance = nil, &) : String?
    Finder.find(name, tolerance) do |sn|
      yield sn
    end
  end

  # Finds the best match for *name* among strings provided in *all_names*.
  # *tolerance* can be used to set maximum Levenshtein distance allowed.
  #
  # ```
  # require "levenshtein"
  #
  # Levenshtein.find("hello", ["hullo", "hel", "hall", "hell"], 2) # => "hullo"
  # Levenshtein.find("hello", ["hurlo", "hel", "hall"], 1)         # => nil
  # ```
  def self.find(name, all_names, tolerance = nil) : String?
    Finder.find(name, all_names, tolerance)
  end
end
