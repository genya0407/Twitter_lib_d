
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
    
class Twitter{
    
    string[string] oauth;
    
    this(string CK, string CS, string AT = "", string AS = "" /+ string AT, string AS +/){
        oauth["CK"] = CK;
        oauth["CS"] = CS;
        if(AT != "" && AS != ""){
            oauth["AT"] = AT;
            oauth["AS"] = AS;
        }
    }
    
    private auto requesting(string[string] options, string url, string method){
        string[string] parameters = parametering();
        
        if(options != ["":""]) foreach(key; options.keys) parameters[key] = options[key];
        
        auto sig = signature([oauth["CS"], oauth["AS"]].join("&"), url, method, parameters);
        parameters["oauth_signature"] = sig;
        foreach(key; options.keys) parameters.remove(key);
        
        auto header = headering(parameters);
        auto data = map!(x => x ~ "=" ~ options[x])(options.keys.sort).join("&");    
        
        // request
        auto http = HTTP();
        http.addRequestHeader("Authorization", header);
        char[] result;
        
        if(data != "="){
            if(method == "POST") result = post(url, data, http);
            else if(method == "GET") result = get(url ~ "?" ~ data, http);
        }else{
            if(method == "GET") result = get(url, http);
        }
        
        // 整形
        return parseJSON(result);
    }
    
    private string[string] oauth_tool(){
        return oauth;
    }
    
    private string signature(string key, string url, string method, string[string] parameters){
        return encodeComponent(to!(string)(Base64.encode((hmac_sha1(key, join([method,encodeComponent(url),encodeComponent(map!(x => x ~ "=" ~ parameters[x])(parameters.keys.sort).join("&"))], "&"))))));
    }
    
    private string headering(string[string] params){
        return "OAuth " ~ map!(x => x ~ "=" ~ "\"" ~ params[x] ~ "\"")(params.keys.sort).join(", ");
    }

    private string[string] parametering(){
        return ["oauth_consumer_key":oauth["CK"],"oauth_nonce":iota(0,32).map!(a=>letters[uniform(0, letters.length)])().array(),"oauth_signature_method":"HMAC-SHA1", "oauth_timestamp":to!(string)(Clock.currTime.toUnixTime),"oauth_token":oauth["AT"],"oauth_version":"1.0"];
    }
    
/************************************************************************************************************************************/
    
    /+ Timelines +/
        public auto mentions_timeline(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/statuses/mentions_timeline.json";
            return requesting(options, url, "GET");
        }
        
        public auto user_timeline(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/statuses/user_timeline.json";
            if(options["user_id"] == "" && options["screen_name"] == ""){writeln("error: set screen_name or user_id"); }
            return requesting(options, url, "GET");
            }
        
        public auto home_timeline(string[string] options = ["":""] ){
            string url = "https://api.twitter.com/1.1/statuses/home_timeline.json";
            return requesting(options, url, "GET");
        }
        
        public auto retweets_of_me(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/statuses/retweets_of_me.json";
            return requesting(options, url, "GET");
        }
    
    /+ Tweets +/
        public auto retweets(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/statuses/retweets/" ~ options["id"] ~ ".json";
            return requesting(options, url, "GET");
        }
        
        public auto show(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/statuses/show.json";
            return requesting(options, url, "GET");
        }
        
        public auto destroy(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/statuses/destroy/" ~ options["id"] ~ ".json";
            return requesting(options, url, "POST");
        }
        
        public auto update(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/statuses/update.json";
            options["status"] = encodeComponent(options["status"]);

            return requesting(options, url, "POST");
        }
        
        public auto retweet(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/statuses/retweet/" ~ options["id"] ~ ".json";

            return requesting(options, url, "POST");
        }
        
        public auto update_with_media(){
            return null;
        }
        
        public auto oembed(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/statuses/oembed.json";

            return requesting(options, url, "GET");
        }
    
    /+ Search +/
        public auto search(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/search/tweets.json";

            return requesting(options, url, "GET");
        }
    
    /+ Streaming +/ //動きません
        /+
        public auto filter(string[string] options = ["":""]){
            string url = "https://stream.twitter.com/1.1/statuses/filter.json";

            return requesting(options, url, "POST");
        }
        
        public auto sample(string[string] options = ["":""]){
            string url = "https://stream.twitter.com/1.1/statuses/sample.json";

            return streaming(options, url, "POST");
        }
        
        public auto firehose(string[string] options = ["":""]){
            string url = "https://stream.twitter.com/1.1/statuses/firehose.json";

            return requesting(options, url, "POST");
        }
        
        public auto user(string[string] options = ["":""]){
            string url = "https://userstream.twitter.com/1.1/user.json";

            return requesting(options, url, "POST"); 
        }
        
        public auto site(string[string] options = ["":""]){
            string url = "https://sitestream.twitter.com/1.1/site.json";

            return requesting(options, url, "POST");
        }
        +/
    /+ Direct Messages +/
        public auto direct_messages(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/direct_messages.json";
            return requesting(options, url, "GET");
        }
        
        public auto direct_messages_sent(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/direct_messages/sent.json";
            return requesting(options, url, "GET");
        }
        
        public auto direct_messages_show(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/direct_messages/show.json";
            return requesting(options, url, "GET");
        }
        
        public auto direct_messages_destroy(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/direct_messages/destroy.json";
            return requesting(options, url, "POST");
        }
        
        public auto direct_messages_new(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/direct_messages/new.json";
            return requesting(options, url, "POST");
        }
    
    /+ Friends & Followers +/
        public auto no_retweets_ids(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/friendships/no_retweets/ids.json";
            return requesting(options, url, "GET");
        }
        
        public auto friends_ids(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/friends/ids.json";
            return requesting(options, url, "GET");
        }
        
        public auto followers_ids(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/followers/ids.json";
            return requesting(options, url, "GET");
        }
        
        public auto lookup(string[string] options = ["":""]){
            string url = "http://api.twitter.com/1.1/friendships/lookup.json";
            return requesting(options, url, "GET");
        }
        
        public auto incoming(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/friendships/incoming.json";
            return requesting(options, url, "GET");
        }
        
        public auto outgoing(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/friendships/outgoing.json";
            return requesting(options, url, "GET");
        }
        
        public auto friendships_create(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/friendships/create.json";
            return requesting(options, url, "POST");
        }
        
        public auto friendships_destroy(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/friendships/destroy.json";
            return requesting(options, url, "POST");
        }
        
        public auto friendships_updata(string[string] options = ["":""]){
            string url = "http://api.twitter.com/1.1/friendships/update.json";
            return requesting(options, url, "POST");
        }
        
        public auto friendships_show(string[string] options = ["":""]){
            string url = "http://api.twitter.com/1.1/friendships/show.json";
            return requesting(options, url, "GET");
        }
        
        public auto friends_list(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/friends/list.json";
            return requesting(options, url, "GET");
        }
        
        public auto followers_list(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/followers/list.json";
            return requesting(options, url, "GET");
        }
    
    /+ Accounts +/
        public auto account_settings(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/settings.json";
            return requesting(options, url, "GET");
        }
        
        public auto account_verify_credentials(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/verify_credentials.json";
            return requesting(options, url, "GET");
        }
        
        public auto set_account(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/settings.json";
            return requesting(options, url, "POST");
        }
        
        public auto update_delivery_device(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/update_delivery_device.json";
            return requesting(options, url, "POST");
        }
        
        public auto update_profile(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/update_profile.json";
            return requesting(options, url, "POST");
        }
        
        public auto update_profile_background_image(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/update_profile_background_image.json";
            return requesting(options, url, "POST");
        }
        
        public auto update_profile_colors(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/update_profile_colors.json";
            return requesting(options, url, "POST");
        }
        
        public auto update_profile_image(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/update_profile_image.json";
            return requesting(options, url, "POST");
        }
        
        public auto remove_profile_banner(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/remove_profile_banner.json";
            return requesting(options, url, "POST");
        }
        
        public auto update_profile_banner(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/account/update_profile_banner.json";
            return requesting(options, url, "POST");
        }
        
    /+ Blocks +/
        public auto blocks_list(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/blocks/list.json";
            return requesting(options, url, "GET");
        }
        
        public auto blocks_ids(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/blocks/ids.json";
            return requesting(options, url, "GET");
        }
        
        public auto blocks_create(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/blocks/create.json";
            return requesting(options, url, "POST");
        }
        
        public auto blocks_destroy(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/blocks/destroy.json";
            return requesting(options, url, "POST");
        }
        
    /+ Users +/
        public auto users_lookup(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/users/lookup.json";
            return requesting(options, url, "POST");
        }        
        
        public auto users_show(string[string] options = ["":""]){
            string url = "http://api.twitter.com/1.1/users/show.json";
            return requesting(options, url, "GET");
        }
        
        public auto users_search(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/users/search.json";
            return requesting(options, url, "GET");
        }
        
        public auto users_contributees(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/users/contributees.json";
            return requesting(options, url, "GET");
        }
        
        public auto users_contributors(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/users/contributors.json";
            return requesting(options, url, "GET");
        }
        
        public auto users_profile_banner(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/users/profile_banner.json";
            return requesting(options, url, "GET");
        }
        
    /+ Suggested Users +/
        public auto suggestions_userlist(string[string] options = ["":""]){
            string url = "http://api.twitter.com/1.1/users/suggestions/" ~ options["slug"] ~ ".json";
            options.remove("slug");
            return requesting(options, url, "GET");
        }
        
        public auto suggestions_category(string[string] options = ["":""]){
            string url = "http://api.twitter.com/1.1/users/suggestions.json";
            return requesting(options, url, "GET");
        }
        
        public auto suggestions_statuses(string[string] options = ["":""]){
            string url = "http://api.twitter.com/1.1/users/suggestions/" ~ options["slug"] ~ "/members.json";
            return requesting(options, url, "GET");
        }
    
    /+ Favorites +/
        public auto favorites_list(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/favorites/list.json";
            return requesting(options, url, "GET");
        }
        
        public auto favorites_destroy(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/favorites/destroy.json";
            return requesting(options, url, "POST");
        }
        
        public auto favorites_create(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/favorites/create.json";
            return requesting(options, url, "POST");
        }
        
    /+ Lists +/
        public auto my_lists(string[string] options = ["":""]){
            string url = "http://api.twitter.com/1.1/lists/list.json";
            return requesting(options, url, "GET");
        }
        
        public auto list_statuses(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/statuses.json";
            return requesting(options, url, "GET");
        }
        
        public auto destroy_list_member(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/members/destroy.json";
            return requesting(options, url, "POST");
        }
        
        public auto list_subscribers(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/subscribers.json";
            return requesting(options, url, "GET");
        }
        
        public auto list_subscribers_create(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/subscribers/create.json";
            return requesting(options, url, "POST");
        }
        
        public auto list_subscribers_show(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/subscribers/show.json";
            return requesting(options, url, "GET");
        }
        
        public auto list_subscribers_destroy(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/subscribers/destroy.json";
            return requesting(options, url, "POST");
        }
        public auto list_members_create_all(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/members/create_all.json";
            return requesting(options, url, "POST");
        }
        
        public auto list_members_show(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/members/show.json";
            return requesting(options, url, "GET");
        }
        public auto list_members(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/members.json";
            return requesting(options, url, "GET");
        }
        public auto list_members_create(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/members/create.json";
            return requesting(options, url, "POST");
        }
        
        public auto list_destroy(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/destroy.json";
            return requesting(options, url, "POST");
        }
        
        public auto list_update(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/update.json";
            return requesting(options, url, "POST");
        }
        
        public auto list_create(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/create.json";
            return requesting(options, url, "POST");
        }
        
        public auto list_show(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/show.json";
            return requesting(options, url, "GET");
        }
        
        public auto list_subscriptions(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/subscriptions.json";
            return requesting(options, url, "GET");
        }
        public auto list_member_destroy_all(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/members/destroy_all.json";
            return requesting(options, url, "POST");
        }
        
        public auto list_ownerships(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/lists/ownerships.json";
            return requesting(options, url, "GET");
        }
        
    /+ Saved Searches +/
        public auto saved_searches_list(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/saved_searches/list.json";
            return requesting(options, url, "GET");
        }
        
        public auto show_saved_searches(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/saved_searches/show/:"~options["id"]~".json";
            return requesting(options, url, "GET");
        }
        
        public auto create_saved_searches(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/saved_searches/create.json";
            return requesting(options, url, "POST");
        }
        
        public auto destroy_saved_searches(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/saved_searches/destroy/"~options["id"]~".json";
            return requesting(options, url, "POST");
        }
        
    /+ Places & Geo +/
        public auto geo_place_id(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/geo/id/"~options["place_id"]~".json";
            return requesting(options, url, "GET");
        }
        
        public auto reverse_geocode(string[string] options = ["":""]){
            string url = "http://api.twitter.com/1.1/geo/reverse_geocode.json";
            return requesting(options, url, "GET");
        }
        
        public auto search_geo(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/geo/search.json";
            return requesting(options, url, "GET");
        }
        
        public auto geo_similar_places(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/geo/similar_places.json";
            return requesting(options, url, "GET");
        }
        
        public auto geo_place(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/geo/place.json";
            return requesting(options, url, "POST");
        }
        
    /+ Trends +/
        public auto trend_place(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/trends/place.json";
            return requesting(options, url, "GET");
        }
        
        public auto trend_available(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/trends/available.json";
            return requesting(options, url, "GET");
        }
        
        public auto trend_closest(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/trends/closest.json";
            return requesting(options, url, "GET");
        }
        
    /+ Spam Reporting +/
        public auto report_spam(string[string] options = ["":""]){
            string url = "https://api.twitter.com/1.1/users/report_spam.json";
            return requesting(options, url, "POST");
        }
        
    /+ OAuth +/
        public auto oauth_authenticate(string[string] options = ["":""]){
            string url = "https://api.twitter.com/oauth/authenticate";
            return requesting(options, url, "GET");
        }
        
        public auto oauth_authorize(string[string] options = ["":""]){
            string url = "https://api.twitter.com/oauth/authorize";
            return requesting(options, url, "GET");
        }
        
        public auto oauth_access_token(string[string] options = ["":""]){
            string url = "https://api.twitter.com/oauth/access_token";
            return requesting(options, url, "POST");
        }
        
        public auto oauth_request_token(string[string] options = ["":""]){
            string url = "https://api.twitter.com/oauth/request_token";
            return requesting(options, url, "POST");
        }
        
        public auto oauth2_token(string[string] options = ["":""]){
            string url = "https://api.twitter.com/oauth2/token";
            return requesting(options, url, "POST");
        }
        
        public auto oauth2_invalidate_token(string[string] options = ["":""]){
            string url = "https://api.twitter.com/oauth2/invalidate_token";
            return requesting(options, url, "POST");
        }
        
    /+ Help +/
        
        
    /+ OAuth method +/
        private auto parametering_oauth(string[string] options = ["":""]){
            if(options != ["":""]){
                auto res = ["oauth_consumer_key":oauth["CK"],"oauth_nonce":iota(0,32).map!(a=>letters[uniform(0, letters.length)])().array(),"oauth_signature_method":"HMAC-SHA1", "oauth_timestamp":to!(string)(Clock.currTime.toUnixTime),"oauth_version":"1.0"];
                foreach(elem; options.keys){
                    res[elem] = options[elem];
                }
                return res;
            }else{
                return ["oauth_consumer_key":oauth["CK"],"oauth_nonce":iota(0,32).map!(a=>letters[uniform(0, letters.length)])().array(),"oauth_signature_method":"HMAC-SHA1", "oauth_timestamp":to!(string)(Clock.currTime.toUnixTime),"oauth_version":"1.0"];
            }
        }
        
        public auto auth_url(){
            auto url = "https://api.twitter.com/oauth/request_token";
            
            auto method = "GET";
            auto parameters = parametering_oauth;//["oauth_consumer_key":CK,"oauth_nonce":iota(0,32).map!(a=>letters[uniform(0, letters.length)])().array(),"oauth_signature_method":"HMAC-SHA1", "oauth_timestamp":to!(string)(Clock.currTime.toUnixTime),"oauth_version":"1.0"];
            
            auto sig = signature(oauth["CS"]~"&", url, method, parameters);
            
            parameters["oauth_signature"] = sig;
            string data = map!(a => a~"="~parameters[a])(parameters.keys.sort).array().join("&");
            
            auto res = get([url,data].join("?")).to!(string)();
            auto a = res.split("&").map!(a => a.split("="))().array();
            string[string] res_obj;
            foreach(elem; a){
                res_obj[elem[0]] = elem[1];
            }
    
            return res_obj;
        }
        
        public void verify(string pin, string oauth_token, string oauth_token_secret){
            auto url = "https://api.twitter.com/oauth/authorize";
            auto method = "GET";
            auto parameters = ["oauth_consumer_key":oauth["CK"],"oauth_nonce":iota(0,32).map!(a=>letters[uniform(0, letters.length)])().array(),"oauth_signature_method":"HMAC-SHA1", "oauth_timestamp":to!(string)(Clock.currTime.toUnixTime),"oauth_version":"1.0"];
            parameters["oauth_token"] = oauth_token;
            parameters["oauth_verifier"] = pin;
            auto sig = signature([oauth["CS"], oauth_token_secret].join("&"), url, method, parameters);
            parameters["oauth_signature"] = sig;
            
            auto http = HTTP();
            http.addRequestHeader("Authorization","OAuth");
            auto res = get(url~"?"~parameters.keys.map!(a => a~"="~parameters[a])().array().join("&"));
            writeln(res);
        }
        
}

