$range = 1..1000; 
$IntList=[System.Collections.Generic.List[int]]::new(); 
$IntArray = @(); 
write-output "List method(ms): $((measure-command -expression { $range | %{ $IntList.Add($_)}}).TotalMilliseconds)" 
write-output "Array method(ms): $((measure-command -expression {$range | % {$IntArray += $_}}).TotalMilliseconds)"