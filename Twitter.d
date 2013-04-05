
module Twitter;

import std.digest.sha, std.net.curl, std.json, std.stdio, std.base64, std.uri, std.conv, std.algorithm, std.range, std.ascii, std.random, std.datetime, std.array;

ubyte[20] hmac_sha1(string key, string message){
    immutable int B = 64;
    
    ubyte[] byte_key;
        foreach(b; key) byte_key ~= b.to!ubyte();
    
    ubyte[] byte_message;
        foreach(b; message) byte_message ~= b.to!ubyte();
    
    
    ubyte[B] ipad = iota(0,B).map!(a=>0x36)().array().map!(a=>a.to!ubyte())().array();
    ubyte[B] opad = iota(0,B).map!(a=>0x5c)().array().map!(a=>a.to!ubyte())().array();
    
    if(byte_key.length > B) byte_key = sha1Of(byte_key);
    
    int count = B - byte_key.length.to!int();
    for(int i = 0; i < count; i++) byte_key ~= [0];
    
    ubyte[B] primeHashText;
    for(int i=0; i < B; i++) primeHashText[i] = to!ubyte(byte_key[i] ^ ipad[i]);
    
    ubyte[B] secondaryHashText;
    for(int i=0; i < B; i++) secondaryHashText[i] = to!ubyte(byte_key[i] ^ opad[i]);
    
    ubyte[20] result = sha1Of(secondaryHashText ~ sha1Of(primeHashText ~ byte_message));
    
    return result;
}


class Twitter{
    
    string[string] oauth;
    
    struct Data{
        int count=0;
        long since_id=0;
        long max_id=0;
        long user_id=0;
        long id=0;
        long in_reply_to_status_id=0;
        int maxwidth=0;
        
        string screen_name="";
        string trim_user="false";
        string contributor_details="false";
        string include_entities="true";
        string exclude_replies="false";
        string include_rts="true";
        string include_my_retweet="false";
        string status="";
        string place_id="";
        string display_coordinates="";
        string[2] lat_long;
        string url;
        string hide_media="false";
        string hide_thread="false";
        string omit_script="false";
        string _align="";
        string related="";
        string lang="";
        string q="";
        string[3] geocode;
        string locale="";
        string result_type="";
        string until="";
        string callback="";
        string follow="";
        string track="";
        string locations="";
        string delimited="";
        string stall_warnings="false";
        string _with="";
        string replies="";
        
    }  
    
    this(string CK, string CS, string AT, string AS){
        oauth["CK"] = CK;
        oauth["CS"] = CS;
        oauth["AT"] = AT;
        oauth["AS"] = AS;
    }
    
    private auto dating(in Data data){
		Data d;
		string[string] options;
        
        if(d.count != data.count){ options["count"] = data.count.to!(string)(); }
        if(d.since_id != data.since_id){ options["since_id"] =data.since_id.to!(string)(); }
        if(d.max_id != data.max_id){ options["max_id"] = data.max_id.to!(string)();}
        if(d.user_id != data.user_id){ options["user_id"] = data.user_id.to!(string)();}
        if(d.id != data.id){ options["id"] = data.id.to!(string)(); }
        if(d.in_reply_to_status_id != data.in_reply_to_status_id){ options["in_reply_to_status_id"] = data.in_reply_to_status_id.to!(string)(); }
        if(d.lat_long[0] != data.lat_long[0] || d.lat_long[1] != data.lat_long[1]){ options["lat"] = data.lat_long[0]; options["long"] = data.lat_long[1]; }
        if(d.maxwidth != data.maxwidth){ options["maxwidth"] = data.maxwidth.to!(string)(); }
        
        
        if(d.screen_name != data.screen_name){ options["screen_name"] = data.screen_name;}
        if(d.trim_user != data.trim_user){ options["trim_user"] = data.trim_user;}
        if(d.contributor_details != data.contributor_details){ options["contributor_details"] = data.contributor_details;}
        if(d.include_entities != data.include_entities){ options["include_entities"] = data.include_entities; }
        if(d.exclude_replies != data.exclude_replies){ options["exclude_replies"] = data.exclude_replies; }
        if(d.include_rts != data.include_rts){ options["include_rts"] = data.include_rts; }
        if(d.include_my_retweet != data.include_my_retweet){ options["include_my_retweet"] = data.include_my_retweet;}
        if(d.status != data.status){ options["status"] = data.status; }
        if(d.place_id != data.place_id){ options["place_id"] = data.place_id; }
        if(d.display_coordinates != data.display_coordinates){ options["display_coordinates"] = data.display_coordinates; }
        if(d.url != data.url){ options["url"] = data.url; }
        if(d.hide_media != data.hide_media){options["hide_media"] = data.hide_media;}
        if(d.hide_thread != data.hide_thread){options["hide_thread"] = data.hide_thread;}
        if(d.omit_script != data.omit_script){options["omit_script"] = data.omit_script;}
        if(d._align != data._align){options["align"] = data._align;}
        if(d.related != data.related){options["related"] = data.related;}
        if(d.lang != data.lang){options["lang"] = data.lang;}
        if(d.q != data.q){options["q"] = encodeComponent(data.q);}
        if(d.geocode[2] != data.geocode[2]){options["geocode"] = data.geocode[0] ~ "," ~ data.geocode[1] ~ "," ~ data.geocode[2];}
        if(d.locale != data.locale){options["locale"] = data.locale;}
        if(d.result_type != data.result_type){options["result_type"] = data.result_type;}
        if(d.until != data.until){options["until"] = data.until;}
        if(d.callback != data.callback){options["callback"] = data.callback;}
        if(d.follow != data.follow){options["follow"] = data.follow;}
        if(d.track != data.track){options["track"] = encodeComponent(data.track);}
        if(d.locations != data.locations){options["locations"] = data.locations;}
        if(d.delimited != data.delimited){options["delimited"] = data.delimited;}
        if(d.stall_warnings != data.stall_warnings){options["stall_warnings"] = data.stall_warnings;}
        if(d._with != data._with){options["with"] = data._with;}
        if(d.replies != data.replies){options["replies"] = data.replies;}
        
        
		return options;
	}
    
    private string[string] oauth_tool(){
        return oauth;
    }

    private string signature(string[string] tools,string url, string[string] parameters, string method){
        return encodeComponent(to!(string)(Base64.encode((hmac_sha1(tools["CS"] ~ "&" ~ tools["AS"], join([method,encodeComponent(url),encodeComponent(map!(x => x ~ "=" ~ parameters[x])(parameters.keys.sort).join("&"))], "&"))))));
    }

    private string headering(string[string] params){
        return "OAuth " ~ map!(x => x ~ "=" ~ "\"" ~ params[x] ~ "\"")(params.keys.sort).join(", ");
    }

    private string[string] parametering(string[string] tools){
        return ["oauth_consumer_key":tools["CK"],"oauth_nonce":iota(0,32).map!(a=>letters[uniform(0, letters.length)])().array(),"oauth_signature_method":"HMAC-SHA1", "oauth_timestamp":to!(string)(Clock.currTime.toUnixTime),"oauth_token":tools["AT"],"oauth_version":"1.0"];
    }

    private auto requesting(string[string] options, string url, string method){
        auto tools = oauth_tool();
        string[string] parameters = parametering(tools);

        foreach(key; options.keys){ parameters[key] = options[key];}
        auto sig = signature(tools, url, parameters, method);
        parameters["oauth_signature"] = sig;
        foreach(key; options.keys){ parameters.remove(key); }
        
        auto header = headering(parameters);
        auto data = map!(x => x ~ "=" ~ options[x])(options.keys.sort).join("&");    
        

        // request
        auto http = HTTP();
        http.addRequestHeader("Authorization", header);
        char[] result;
        if(method == "POST"){
            result = post(url, data, http);
        }else if(method == "GET"){
            result = get(url ~ "?" ~ data, http);
        }
        
        
        // 整形
        auto jsn =parseJSON(result);
        JSONValue[] tweets;
        
        JSON_TYPE jsn_type;
        if(jsn.type == jsn_type.ARRAY){
            foreach(elem; jsn.array){
                tweets ~= elem;
            } 
        }else if(jsn.type == jsn_type.OBJECT){
            if(jsn.object.length < 10){
                foreach(elem; jsn.object["statuses"].array){
                    tweets ~= elem;
                }
            }else{
                return [jsn];
            }
        }

        return tweets;
    }
    
    private auto streaming(string[string] options, string url, string method){
        auto tools = oauth_tool();
        string[string] parameters = parametering(tools);

        foreach(key; options.keys){ parameters[key] = options[key];}
        auto sig = signature(tools, url, parameters, method);
        parameters["oauth_signature"] = sig;
        foreach(key; options.keys){ parameters.remove(key); }
        
        auto header = headering(parameters);
        auto data = map!(x => x ~ "=" ~ options[x])(options.keys.sort).join("&");    
        

        // request
        auto http = HTTP();
        http.addRequestHeader("Authorization", header);
        char[] result;
        if(method == "POST"){
            writeln("debug1");
            auto a = byLineAsync("dlang.org").array();
            writeln("debug3");
            auto b = byLineAsync("twitter.com").array();
            writeln("debug4");
            writeln("debug2");
        }else if(method == "GET"){
            result = get(url ~ "?" ~ data, http);
        }
        
        
        // 整形
        auto jsn =parseJSON(result);
        JSONValue[] tweets;
        
        JSON_TYPE jsn_type;
        if(jsn.type == jsn_type.ARRAY){
            foreach(elem; jsn.array){
                tweets ~= elem;
            } 
        }else if(jsn.type == jsn_type.OBJECT){
            if(jsn.object.length < 10){
                foreach(elem; jsn.object["statuses"].array){
                    tweets ~= elem;
                }
            }else{
                return [jsn];
            }
        }

        return tweets;
    }
    
    /********************************************************************************************************************************/
    
    /+ Timelines +/
        public auto mentions_timeline(in Data data){
            string url = "https://api.twitter.com/1.1/statuses/mentions_timeline.json";
            string[string] options = dating(data);
            
            return requesting(options, url, "GET");
        }
        
        public auto user_timeline(in Data data){
            string url = "https://api.twitter.com/1.1/statuses/user_timeline.json";
            string[string] options = dating(data);
            if(data.user_id == 0 && data.screen_name == ""){writeln("error: set screen_name or user_id"); }
            return requesting(options, url, "GET");
            }
        
        public auto home_timeline(in Data data){
            string url = "https://api.twitter.com/1.1/statuses/home_timeline.json";
            string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
        
        public auto retweets_of_me(in Data data){
            string url = "https://api.twitter.com/1.1/statuses/retweets_of_me.json";
            string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
    
    /+ Tweets +/
        public auto retweets(in Data data){
            string url = "https://api.twitter.com/1.1/statuses/retweets/" ~ data.id.to!(string)() ~ ".json";
            string[string] options =dating(data);
            return requesting(options, url, "GET");
        }
        
        public auto show(in Data data){
            string url = "https://api.twitter.com/1.1/statuses/show.json";
            string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
        
        public auto destroy(in Data data){
            string url = "https://api.twitter.com/1.1/statuses/destroy/" ~ data.id.to!(string)() ~ ".json";
            string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto update(Data data){
            string url = "https://api.twitter.com/1.1/statuses/update.json";
            data.status = encodeComponent(data.status);
            string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto retweet(in Data data){
            string url = "https://api.twitter.com/1.1/statuses/retweet/" ~ data.id.to!(string)() ~ ".json";
            string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto updata_with_media(){
            return null;
        }
        
        public auto oembed(in Data data){
            string url = "https://api.twitter.com/1.1/statuses/oembed.json";
            string[string] options = dating(data);
            return requesting(options, url, "GET");
        }

    /+ Search +/
        public auto search(in Data data){
            string url = "https://api.twitter.com/1.1/search/tweets.json";
            string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
    
    /+ Streaming +/
        public auto filter(in Data data){
            string url = "https://stream.twitter.com/1.1/statuses/filter.json";
            string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto sample(in Data data){
            string url = "https://stream.twitter.com/1.1/statuses/sample.json";
            string[string] options = dating(data);
            return streaming(options, url, "POST");
        }
        
        public auto firehose(in Data data){
            string url = "https://stream.twitter.com/1.1/statuses/firehose.json";
            string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto user(in Data data){
            string url = "https://userstream.twitter.com/1.1/user.json";
            string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto site(in Data data){
            string url = "https://sitestream.twitter.com/1.1/site.json";
            string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
    
    /+ Direct Messages +/

}

