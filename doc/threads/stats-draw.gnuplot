set datafile columnheaders
set datafile separator ";"
#set isosample 15
set dgrid3d 8,8
set logscale
set view 80,15,1,1
set autoscale xy
#set pm3d

set term pdfcairo size 20cm,15cm

set xlabel "TOTAL ROUTES" offset 0,-1.5
set xrange [10000:320000]
set xtics offset 0,-0.5
set xtics (10000,15000,30000,50000,100000,150000,300000)

set ylabel "PEERS"
#set yrange [10:320]
#set ytics (10,15,30,50,100,150,300)
set yrange [10:320]
set ytics (10,15,30,50,100,150,300)

set zrange [1:2000]
set xyplane at 1

set border 895

#set grid ztics lt 20

set output ARG1 . "-" . ARG4 . ".pdf"

splot \
  ARG1 . ".csv" \
    using "TOTAL_ROUTES":"PEERS":ARG2."/".ARG4 \
    with lines \
    title ARG2."/".ARG4, \
  "" \
    using "TOTAL_ROUTES":"PEERS":ARG3."/".ARG4 \
    with lines \
    title ARG3."/".ARG4

