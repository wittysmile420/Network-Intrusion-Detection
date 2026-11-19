# NS2-compatible, defensive lab topology. Run with: ns ns2_topology.tcl normal
set scenario [lindex $argv 0]
if {$scenario == ""} {set scenario normal}
file mkdir simulations/results
set ns [new Simulator]
set trace [open "simulations/results/${scenario}.tr" w]
$ns trace-all $trace
set nam [open "simulations/results/${scenario}.nam" w]
$ns namtrace-all $nam
for {set i 0} {$i < 4} {incr i} {set n($i) [$ns node]}
$ns duplex-link $n(0) $n(1) 10Mb 10ms DropTail
$ns duplex-link $n(1) $n(2) 10Mb 10ms DropTail
$ns duplex-link $n(2) $n(3) 10Mb 10ms DropTail
if {$scenario == "abnormal"} {
    set abnormal_queue [[$ns link $n(0) $n(1)] queue]
    $abnormal_queue set limit_ 5
}
set udp [new Agent/UDP]; $ns attach-agent $n(0) $udp
set null [new Agent/Null]; $ns attach-agent $n(3) $null; $ns connect $udp $null
set cbr [new Application/Traffic/CBR]; $cbr set packetSize_ 512; $cbr set interval_ [expr {$scenario == "abnormal" ? 0.0001 : 0.05}]; $cbr attach-agent $udp
proc finish {} {global ns trace nam; $ns flush-trace; close $trace; close $nam; exit 0}
$ns at 0.5 "$cbr start"; $ns at 9.5 "$cbr stop"; $ns at 10.0 "finish"; $ns run

