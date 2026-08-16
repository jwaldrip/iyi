enum SpecChannelStatus
  Begin
  End
  Timeout
end

def schedule_timeout(c : Channel(SpecChannelStatus))
  spawn do
    sleep 1.second
    c.send(SpecChannelStatus::Timeout)
  end
end
