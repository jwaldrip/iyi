require "../../spec_helper"

describe "Code gen: asm" do
  # TODO: arm asm tests
  {% if flag?(:i386) || flag?(:x86_64) %}
    it "passes correct string length to LLVM" do
      run <<-CODE
        asm("// 😂😂
        nop
        nop")
        CODE
    end

    it "codegens without inputs" do
      run(<<-CODE).to_i.should eq(1234)
        dst = uninitialized Int32
        asm("mov $$1234, $0" : "=r"(dst))
        dst
        CODE
    end

    it "codegens with two outputs" do
      run(<<-CODE).to_i.should eq(0x12345678)
        dst1 = uninitialized Int32
        dst2 = uninitialized Int32
        asm("
          mov $$0x1234, $0
          mov $$0x5678, $1" : "=r"(dst1), "=r"(dst2))
        (dst1.unsafe_shl(16)) | dst2
        CODE
    end

    it "codegens with one input" do
      run(<<-CODE).to_i.should eq(1234)
        src = 1234
        dst = uninitialized Int32
        asm("mov $1, $0" : "=r"(dst) : "r"(src))
        dst
        CODE
    end

    it "codegens with two inputs" do
      run(<<-CODE).to_i.should eq(42)
        c = uninitialized Int32
        a = 20
        b = 22
        asm(
          "add $2, $0"
             : "=r"(c)
             : "0"(a), "r"(b)
          )
        c
        CODE
    end

    it "codegens with intel dialect" do
      run(<<-CODE).to_i.should eq(1234)
        dst = uninitialized Int32
        asm("mov dword ptr [$0], 1234" :: "r"(pointerof(dst)) :: "intel")
        dst
        CODE
    end
  {% end %}
end
