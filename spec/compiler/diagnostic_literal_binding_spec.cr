require "../support/syntax"

describe Iyi::DiagnosticReplayJournal do
  it "derives a character value from the exact scanned token" do
    token = Iyi::DiagnosticRenderedToken.new(0, 4, "CHAR", "'\\n'", "Crystal", value_base64: "Cg==")
    journal = Iyi::DiagnosticReplayJournal.new([token, token])
    witness = Iyi::DiagnosticLiteralWitness.new(Iyi::DiagnosticLiteralWitnessKind::StringPiece, 0, 4)
    production = Iyi::DiagnosticLiteralProductionSegment.new(Iyi::DiagnosticLiteralProduction::CharToken,
      0, 4, "J1xuJw==", nil, nil, nil, nil, [witness])
    journal.literal_atom!(production, "Crystal").should eq("\n")
  end

  it "refuses conflicting observations at the same offset" do
    char = Iyi::DiagnosticRenderedToken.new(0, 3, "CHAR", "'a'", "Crystal", value_base64: "YQ==")
    other = Iyi::DiagnosticRenderedToken.new(0, 3, "SYMBOL", "'a'", "Crystal", value_base64: "YQ==")
    journal = Iyi::DiagnosticReplayJournal.new([char, other])
    expect_raises(ArgumentError, "ambiguous scanned token") do
      journal.literal_entry!(0, 3, "CHAR", "Crystal")
    end
  end
end
