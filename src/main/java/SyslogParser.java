
import org.xml.sax.SAXException;

import java.io.*;

import java.util.HashMap;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


//Parse Win Event(not events!) from syslog formatted string by one
public class SyslogParser{
    private  String eventFromSyslog;
    private  Map<String, String> logMap;


    private   String makeDataCleanUp(String data){
        data = removeUnnecessaryData( data);
        data = removeUnlogic( data);
        return data;
    }

    private   String removeUnlogic(String data){
        return data.replaceAll(":\\s{1,}", "="); //rm unlogical pairs wch contain ":\\s{3,}"
    }

    private   String removeUnnecessaryData(String data){ //rm <number> in the beginning of the event data
        return data.replaceAll("<\\d+>", "");
    }



    private  Map<String,String> getLogMap(String[] logPairs){
        Map<String,String> logMap = new HashMap<>();

        for(String pair : logPairs)                        //iterate over the pairs
        {
            String[] entry = pair.split("=");

            for (String str: entry    ) {
                //System.out.println(str);
            }
            if(entry.length < 2)
                logMap.put(entry[0], null);
            else if(entry.length <= 2){
                logMap.put(entry[0], entry[1]);
            }
        }
        return logMap;
    }

    public  void parseWindowsEvent() throws  SAXException,
            IOException, IllegalArgumentException{
        String eventLogWithoutErrors = makeDataCleanUp(eventFromSyslog);
        System.out.println("");
        Matcher m = Pattern.compile("(^.*?[a-zA-Z]{3,}\\s\\d{2,}\\s\\d{2,}:\\d{2,}:\\d{2,}\\s)", Pattern.CASE_INSENSITIVE).matcher(eventLogWithoutErrors);
        while (m.find()) {
            eventLogWithoutErrors = eventLogWithoutErrors.replaceAll(m.group(1).toString(), "");

        }

        Matcher m2 = Pattern.compile("(^.*?\\d+\\.\\d+\\.\\d+\\.\\d+\\s)", Pattern.CASE_INSENSITIVE).matcher(eventLogWithoutErrors);
        while (m2.find()) {
            eventLogWithoutErrors = eventLogWithoutErrors.replaceAll(m2.group(1).toString(), "");

        }

        String[] pairs = eventLogWithoutErrors.split("\\s{3,}");


        logMap = getLogMap(pairs);
    }
    public  void printData()throws SAXException,
            IOException, IllegalArgumentException{
        for(Map.Entry<String, String> entry: logMap.entrySet()){
            System.out.println(entry.getKey() + ":" + entry.getValue());
        }
    }
    public   SyslogParser(String data) throws UnsupportedEncodingException {
        this.eventFromSyslog = data;
    }




}