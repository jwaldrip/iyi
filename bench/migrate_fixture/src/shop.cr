require "./shop/config"
require "./shop/models/cart"
require "./shop/price-list"
require "./shop/models/item"
require "./shop/counter"
require "./shop/report"

cart = Shop::Models::Cart.new
cart.add(Shop::Models::Item.new("kahve", 90))
cart.add(Shop::Models::Item.new("çay", 40))
cart.add(Shop::Models::Item.new("simit", 15))

puts Shop.banner
puts Shop::Names.title("cart")
puts cart.note
puts cart.note?.nil?
report = Shop::Report.new(cart)
puts "#{report.owed} owed, priced? #{report.priced?}"
puts Shop::PriceList.dearest(cart.items).name
puts Shop::Counter.twice(cart.total)
puts Shop::Counter.priced(Shop::Models::Item.new("kahve", 90))
puts cart.tidy!
puts cart.total
puts Shop::Counter.report(cart.total)
puts cart.dearest.label
puts cart.cheapest_first.map(&.name).join(", ")
puts cart.items.first.in?(cart)
puts cart.holds?(Shop::Models::Item.new("kahve", 90))
puts Shop::Report.new(cart).to_s.lines.size
