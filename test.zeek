global dict : table[addr] of set[string] = table();
global uri:string;
global replysum:table[addr] of int;
global errorsum:table[addr] of int;
global mycount:int;
global myaddr:addr;
global mysum:int;


event zeek_init()
{
local r1=SumStats::Reducer($stream="http.lookup", $apply=set(SumStats::SUM));
local r2=SumStats::Reducer($stream="http.404.lookup", $apply=set(SumStats::SUM));
SumStats::create([$name = "111",
                      $epoch = 10min,
                      $reducers = set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        myaddr=key$host;
                        mysum=result["http.lookup"]$sum;
                        if (myaddr in replysum)
                        {replysum[myaddr]+=mysum;}
                        else {replysum[myaddr]=mysum;}
                        }]);
SumStats::create([$name = "222",
                      $epoch = 10min,
                      $reducers = set(r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        myaddr=key$host;
                        mysum=result["http.404.lookup"]$sum;
                        if (myaddr in errorsum)
                        {errorsum[myaddr]+=mysum;}
                        else {errorsum[myaddr]=mysum;}
                        }]);


}
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
uri=original_URI;
}
event http_reply(c: connection, version: string, code: count, reason: string)
{
SumStats::observe("http.lookup", 
                      SumStats::Key($host=c$id$orig_h), 
                      SumStats::Observation($num=1));
if(code==404)
{
SumStats::observe("http.404.lookup", 
                      SumStats::Key($host=c$id$orig_h), 
                      SumStats::Observation($num=1));

if (c$id$orig_h in dict){
if (to_lower(uri) !in dict[c$id$orig_h]){
add dict[c$id$orig_h][to_lower(uri)];
}
}
else{
dict[c$id$orig_h]=set(to_lower(uri));
}
}

}

event zeek_done()
{
for (a in replysum)
{
if (replysum[a]>2)
{
if (a in errorsum)
{
if(errorsum[a]/replysum[a]>0.2)
{
if (a in dict)
{
mycount=0;
for (myuri in dict[a])
{++mycount;}
if (mycount/errorsum[a]>0.5)
{print fmt("%s is a scanner with %d scan attemps on %d urls", a,errorsum[a],mycount);}
}

}
}
}
}

}
