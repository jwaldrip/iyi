require "ecr"
require "./config"
require "./models/cart"

module Shop
  class Report
    def initialize(@cart : Models::Cart)
    end

    # A template embedded at compile time, named from the project root:
    # code the migration has to carry and rewrite.
    ECR.def_to_s "src/shop/views/report.html.ecr"
  end
end
