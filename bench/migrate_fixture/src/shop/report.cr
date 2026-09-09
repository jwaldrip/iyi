require "ecr"
require "./config"
require "./models/cart"

module Shop
  # The annotation is another module's, applied here; `Money` is another
  # module's name for a type, written in a signature here.
  @[Shop::Priced]
  class Report
    def initialize(@cart : Models::Cart)
    end

    def owed : Shop::Money
      @cart.total
    end

    def priced? : Bool
      {{ @type.annotation(Shop::Priced) ? true : false }}
    end

    # A template embedded at compile time, named from the project root:
    # code the migration has to carry and rewrite.
    ECR.def_to_s "src/shop/views/report.html.ecr"
  end
end
