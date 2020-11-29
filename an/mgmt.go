package an

// NFD management protcol assigned numbers.
const (
	MgmtControlParameters             = 0x68
	MgmtFaceID                        = 0x69
	MgmtURI                           = 0x72
	MgmtLocalURI                      = 0x81
	MgmtOrigin                        = 0x6F
	MgmtCost                          = 0x6A
	MgmtCapacity                      = 0x83
	MgmtCount                         = 0x84
	MgmtBaseCongestionMarkingInterval = 0x87
	MgmtDefaultCongestionThreshold    = 0x88
	MgmtMTU                           = 0x89
	MgmtFlags                         = 0x6C
	MgmtMask                          = 0x70
	MgmtStrategy                      = 0x6B
	MgmtExpirationPeriod              = 0x6D
	MgmtControlResponse               = 0x65
	MgmtStatusCode                    = 0x66
	MgmtStatusText                    = 0x67

	_ = "enumgen:Mgmt"
)
