
module Twitter;

import std.digest.sha, std.net.curl, std.json, std.stdio, std.base64, std.uri, std.conv, std.algorithm, std.range, std.ascii, std.random, std.datetime, std.array;

ubyte[20] hmac_sha1(string key, string message){
    immutable int B = 64;
    
    ubyte[] byte_key; foreach(b; key) byte_key ~= b.to!ubyte();
    
    ubyte[] byte_message; foreach(b; message) byte_message ~= b.to!ubyte();
    
    ubyte[64] ipad; ipad[] = to!(ubyte)(0x36);
    ubyte[64] opad; opad[] = to!(ubyte)(0x5c);
    
    if(byte_key.length > B) byte_key = sha1Of(byte_key);
    byte_key ~= new ubyte[B - byte_key.length.to!int()];
    
    ubyte[B] primeHashText; for(int i=0; i < B; i++) primeHashText[i] = to!ubyte(byte_key[i] ^ ipad[i]);
    ubyte[B] secondaryHashText; for(int i=0; i < B; i++) secondaryHashText[i] = to!ubyte(byte_key[i] ^ opad[i]);
    
    ubyte[20] result = sha1Of(secondaryHashText ~ sha1Of(primeHashText ~ byte_message));
    return result;
}

/+
JSONValue[] jsonize(string json_str){
switch(elem.object[key].type){
    case Jtype.STRING:
        writeln(elem[key].str);
        break;
    case Jtype.INTEGER:
        writeln(elem[key].integer);
        break;
    case Jtype.UINTEGER:
        writeln(elem[key].uinteger);
        break;
    case Jtype.FLOAT:
        writeln(elem[key].floating);
        break;
    case Jtype.OBJECT:
        //writeln(elem[key].object);
        break;
    case Jtype.ARRAY:
        //writeln(elem[key].array);
        break;
    case Jtype.TRUE:
        //writeln(elem[key].true);
        break;
    case Jtype.FALSE:
        //writeln(elem[key].false);
        break;
    case Jtype.NULL:
        //writeln(elem[key].null);
        break;
    default:
    }
}
+/
    
class Twitter{
    
    string[string] oauth;
    
    this(string CK, string CS, string AT, string AS){
        oauth["CK"] = CK;
        oauth["CS"] = CS;
        oauth["AT"] = AT;
        oauth["AS"] = AS;
    }
    
    private auto requesting(string[string] options, string url, string method){
        auto tools = oauth_tool();
        string[string] parameters = parametering(tools);

        foreach(key; options.keys) parameters[key] = options[key];
        auto sig = signature(tools, url, parameters, method);
        parameters["oauth_signature"] = sig;
        foreach(key; options.keys) parameters.remove(key);
        
        auto header = headering(parameters);
        auto data = map!(x => x ~ "=" ~ options[x])(options.keys.sort).join("&");    
        
        // request
        auto http = HTTP();
        http.addRequestHeader("Authorization", header);
        char[] result;
        if(method == "POST") result = post(url, data, http);
        else if(method == "GET") result = get(url ~ "?" ~ data, http);
        
        // 整形
        auto jsn =parseJSON(result);
        
        /*
        JSONValue[] tweets;
        JSON_TYPE jsn_type;
        if(jsn.type == jsn_type.ARRAY) foreach(elem; jsn.array) tweets ~= elem;
        else if(jsn.type == jsn_type.OBJECT) if(jsn.object.length < 10) foreach(elem; jsn.object["statuses"].array) tweets ~= elem;
        else return [jsn];
        */

        return jsn;
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
    
/************************************************************************************************************************************/
    
    /+ Timelines +/
        public auto mentions_timeline(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/mentions_timeline.json";
            //string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
        
        public auto user_timeline(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/user_timeline.json";
            //string[string] options = dating(data);
            if(options["user_id"] == "" && options["screen_name"] == ""){writeln("error: set screen_name or user_id"); }
            return requesting(options, url, "GET");
            }
        
        public auto home_timeline(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/home_timeline.json";
            //string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
        
        public auto retweets_of_me(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/retweets_of_me.json";
            //string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
    
    /+ Tweets +/
        public auto retweets(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/retweets/" ~ options["id"] ~ ".json";
            //string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
        
        public auto show(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/show.json";
            //string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
        
        public auto destroy(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/destroy/" ~ options["id"] ~ ".json";
            //string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto update(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/update.json";
            options["status"] = encodeComponent(options["status"]);
            //string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto retweet(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/retweet/" ~ options["id"] ~ ".json";
            //string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto updata_with_media(){
            return null;
        }
        
        public auto oembed(string[string] options){
            string url = "https://api.twitter.com/1.1/statuses/oembed.json";
            //string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
    
    /+ Search +/
        public auto search(string[string] options){
            string url = "https://api.twitter.com/1.1/search/tweets.json";
            //string[string] options = dating(data);
            return requesting(options, url, "GET");
        }
    
    /+ Streaming +/ //動きません
        /+
        public auto filter(string[string] options){
            string url = "https://stream.twitter.com/1.1/statuses/filter.json";
            //string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto sample(string[string] options){
            string url = "https://stream.twitter.com/1.1/statuses/sample.json";
            //string[string] options = dating(data);
            return streaming(options, url, "POST");
        }
        
        public auto firehose(string[string] options){
            string url = "https://stream.twitter.com/1.1/statuses/firehose.json";
            //string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        
        public auto user(string[string] options){
            string url = "https://userstream.twitter.com/1.1/user.json";
            //string[string] options = dating(data);
            return requesting(options, url, "POST"); 
        }
        
        public auto site(string[string] options){
            string url = "https://sitestream.twitter.com/1.1/site.json";
            //string[string] options = dating(data);
            return requesting(options, url, "POST");
        }
        +/
    /+ Direct Messages +/
        public auto direct_messages(string[string] options){
            string url = "https://api.twitter.com/1.1/direct_messages.json";
            return requesting(options, url, "GET");
        }
        
        public auto direct_messages_sent(string[string] options){
            string url = "https://api.twitter.com/1.1/direct_messages/sent.json";
            return requesting(options, url, "GET");
        }
        
        public auto direct_messages_show(string[string] options){
            string url = "https://api.twitter.com/1.1/direct_messages/show.json";
            return requesting(options, url, "GET");
        }
        
        public auto direct_messages_destroy(string[string] options){
            string url = "https://api.twitter.com/1.1/direct_messages/destroy.json";
            return requesting(options, url, "POST");
        }
        
        public auto direct_messages_new(string[string] options){
            string url = "https://api.twitter.com/1.1/direct_messages/new.json";
            return requesting(options, url, "POST");
        }
    
    /+ Friends & Followers +/
        public auto no_retweets_ids(string[string] options){
            string url = "https://api.twitter.com/1.1/friendships/no_retweets/ids.json";
            return requesting(options, url, "GET");
        }
        
        public auto friends_ids(string[string] options){
            string url = "https://api.twitter.com/1.1/friends/ids.json";
            return requesting(options, url, "GET");
        }
        
        public auto followers_ids(string[string] options){
            string url = "https://api.twitter.com/1.1/followers/ids.json";
            return requesting(options, url, "GET");
        }
        
        public auto lookup(string[string] options){
            string url = "http://api.twitter.com/1.1/friendships/lookup.json";
            return requesting(options, url, "GET");
        }
        
        public auto incoming(string[string] options){
            string url = "https://api.twitter.com/1.1/friendships/incoming.json";
            return requesting(options, url, "GET");
        }
        
        public auto outgoing(string[string] options){
            string url = "https://api.twitter.com/1.1/friendships/outgoing.json";
            return requesting(options, url, "GET");
        }
        
        public auto friendships_create(string[string] options){
            string url = "https://api.twitter.com/1.1/friendships/create.json";
            return requesting(options, url, "POST");
        }
        
        public auto friendships_destroy(string[string] options){
            string url = "https://api.twitter.com/1.1/friendships/destroy.json";
            return requesting(options, url, "POST");
        }
        
        public auto friendships_updata(string[string] options){
            string url = "http://api.twitter.com/1.1/friendships/update.json";
            return requesting(options, url, "POST");
        }
        
        public auto friendships_show(string[string] options){
            string url = "http://api.twitter.com/1.1/friendships/show.json";
            return requesting(options, url, "GET");
        }
        
        public auto friends_list(string[string] options){
            string url = "https://api.twitter.com/1.1/friends/list.json";
            return requesting(options, url, "GET");
        }
        
        public auto followers_list(string[string] options){
            string url = "https://api.twitter.com/1.1/followers/list.json";
            return requesting(options, url, "GET");
        }
    
    /+ Accounts +/
        public auto account_settings(string[string] options){
            string url = "https://api.twitter.com/1.1/account/settings.json";
            return requesting(options, url, "GET");
        }
        
        public auto account_verify_credentials(string[string] options){
            string url = "https://api.twitter.com/1.1/account/verify_credentials.json";
            return requesting(options, url, "GET");
        }
        
        public auto set_account(string[string] options){
            string url = "https://api.twitter.com/1.1/account/settings.json";
            return requesting(options, url, "POST");
        }
        
        public auto update_delivery_device(string[string] options){
            string url = "https://api.twitter.com/1.1/account/update_delivery_device.json";
            return requesting(options, url, "POST");
        }
        
        public auto update_profile(string[string] options){
            string url = "https://api.twitter.com/1.1/account/update_profile.json";
            return requesting(options, url, "POST");
        }
        
        public auto update_profile_background_image(string[string] options){
            string url = "https://api.twitter.com/1.1/account/update_profile_background_image.json";
            return requesting(options, url, "POST");
        }
        
        
        
        public auto users_show(string[string] options){
            string url = "http://api.twitter.com/1.1/users/show.json";
            return requesting(options, url, "GET");
        }
        
        
        
}

