require "../spec_helper"
require "./spec_helper"

describe Iyi::Config do
  it ".host_target" do
    {% begin %}
      {% host_triple = Iyi.constant("HOST_TRIPLE") || Crystal::DESCRIPTION.lines[-1].gsub(/^Default target: /, "") %}
      Iyi::Config.host_target.should eq Iyi::Codegen::Target.new({{ host_triple }})
    {% end %}
  end

  {% if flag?(:linux) %}
    it ".linux_runtime_libc" do
      Iyi::Config.linux_runtime_libc.should eq {{ flag?(:musl) ? "musl" : "gnu" }}
    end
  {% end %}
end
