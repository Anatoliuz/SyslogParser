import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;
import org.apache.commons.lang.UnhandledException;
import org.xml.sax.SAXException;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.Executor;


//Parse Win Event(not events!) from syslog formatted string by one
public class SyslogParser{
    private  String eventFromSyslog;
    private  Map<String, String> logMap;
    final public  int MAX_SUPPORTED_VERSION = 1;

    //think about it
    private   InputStream in;
    private   boolean parseTag;
    private  Charset charset;

    /// Push back buffer. -1 indicates that it is empty.
    private  int pushBack = -1;


    private   String makeDataCleanUp(String data){
        //data = removeUnnecessaryData( data);
        data = removeUnlogic( data);
        return data;
    }

    //should be replaced(logical error)
    private  InputStream strToInputStream(String str) throws UnsupportedEncodingException {
        return new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8.name()));
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
        System.out.println(eventLogWithoutErrors);
        in = strToInputStream(eventLogWithoutErrors);
        System.out.println(in.toString());
        workingWithDateAndHostname();

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


    private  Map<String, String> workingWithDateAndHostname() throws IOException{

        int priority = 0;
        int c = read(false);

        // Return null on initial EOF.
        if (c == -1) return null;

        if (c == '<') {
            priority = readInt();

            expect('>');
        }

        int version = 0;
        Calendar cal = null;

        if (Character.isDigit(peek(true))) {
            // Assume ISO date and time
            int y = readInt();

            c = read(true);

            if (c == ' ') {
                // Assume this is a RFC 5424 message.
                version = y;

                if (version > MAX_SUPPORTED_VERSION)
                    throw new IOException("Unsupported syslog version: " + version);

                skipSpaces();
                y = readInt();
                expect('-');
            } else if (c != '-') {
                throw new IOException("Unexpected syslog character: " + (char) c);
            }

            int m = readInt();
            expect('-');
            int d = readInt();

            c = read(true);

            if (c != 'T' && c != ' ')
                throw new IOException("Unexpected syslog character: " + (char) c);

            int hh = readInt();
            expect(':');
            int mm = readInt();
            expect(':');
            int ss = readInt();
            double subss = 0;

            c = read(true);

            if (c == '.') {
                // Fractions of seconds
                subss = readFractions();
                c = read(true);
            }

            int tz = 0;

            if (c == 'Z') {
                // UTC
            } else if (c == '-') {
                tz = readInt();

                if (peek(true) == ':') {
                    read(true);
                    tz = -(tz * 60 + readInt());
                }
            } else if (c == '+') {
                tz = readInt();

                if (peek(true) == ':') {
                    read(true);
                    tz = tz * 60 + readInt();
                }
            }

            cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"), Locale.getDefault());

            cal.set(y, m - 1, d, hh, mm, ss);
            cal.set(Calendar.MILLISECOND, (int) (subss * 1000));
            cal.add(Calendar.MINUTE, tz);
        } else {
            // Assume BSD date and time
            int m = readMonthAbbreviation();

            expect(' ');
            skipSpaces();

            int d = readInt();

            expect(' ');
            skipSpaces();

            int hh = readInt();

            expect(':');

            int mm = readInt();

            expect(':');

            int ss = readInt();

            cal = new GregorianCalendar(Locale.ROOT);

            cal.set(Calendar.MONTH, m);
            cal.set(Calendar.DAY_OF_MONTH, d);
            cal.set(Calendar.HOUR_OF_DAY, hh);
            cal.set(Calendar.MINUTE, mm);
            cal.set(Calendar.SECOND, ss);
        }

        expect(' ');
        skipSpaces();

        String hostname = readWordString(32);

        expect(' ');

        byte[] appname = null;
        byte[] procId = null;
        byte[] msgId = null;
        byte[] structuredData = null;

        if (version >= 1) {
            appname = readWordOrNil(20);
            expect(' ');
            procId = readWordOrNil(20);
            expect(' ');
            msgId = readWordOrNil(20);
            expect(' ');
            structuredData = readStructuredData();
            expect(' ');
        } else if (version == 0 && parseTag) {
            // Try to find a colon terminated tag.
            appname = readTag();
            if (peek(true) == '[') procId = readPid();
            expect(':');
        }

        skipSpaces();

        byte[] msg = readLine(128);
        return createEvent(version, priority, cal, hostname, appname, procId, msgId, structuredData, msg);

    }

    private  int read(boolean checkEof) throws IOException {
        if (pushBack != -1) {
            int c = pushBack;
            pushBack = -1;
            return c;
        }

        int c = in.read();

        if (checkEof && c == -1)
            throw new EOFException("Unexpected end of syslog stream");

        return c;
    }

    private  int readInt() throws IOException {
        int c;
        int ret = 0;

        while (Character.isDigit(c = read(false)))
            ret = ret * 10 + (c - '0');

        if (c != -1) unread(c);

        return ret;
    }
    private  void unread(int c) {
        assert c != -1 : "Trying to push back EOF";
        assert pushBack == -1 : "Trying to push back two bytes";
        pushBack = c;
    }
    private  void expect(int c) throws IOException {
        int d = read(true);

        if (d != c)
            throw new IOException("Unexpected syslog character: " + (char) d);
    }

    private  int peek(boolean checkEof) throws IOException {
        int c = read(checkEof);

        unread(c);

        return c;
    }
    private  void skipSpaces() throws IOException {
        int c;

        while ((c = read(false)) == ' ')
            continue;

        unread(c);
    }
    private  double readFractions() throws IOException {
        int c;
        int ret = 0;
        int order = 1;

        while (Character.isDigit(c = read(false))) {
            ret = ret * 10 + (c - '0');
            order *= 10;
        }

        if (c != -1) unread(c);

        return (double) ret / order;
    }
    private  int readMonthAbbreviation() throws IOException {
        int c;

        switch (read(true)) {
            case 'A':
                switch (read(true)) {
                    case 'p':
                        skipWord();
                        return Calendar.APRIL;

                    case 'u':
                        skipWord();
                        return Calendar.AUGUST;

                    default:
                        return -1;
                }

            case 'D':
                skipWord();
                return Calendar.DECEMBER;

            case 'F':
                skipWord();
                return Calendar.FEBRUARY;

            case 'J':
                read(true); // Second letter is ambiguous.
                read(true); // Third letter is also ambiguous.

                switch (read(true)) {
                    case 'e':
                        skipWord();
                        return Calendar.JUNE;

                    case 'u':
                        skipWord();
                        return Calendar.JANUARY;

                    case 'y':
                        skipWord();
                        return Calendar.JULY;

                    default:
                        return -1;
                }

            case 'M':
                read(true); // Second letter is ambiguous.

                switch (read(true)) {
                    case 'r':
                        skipWord();
                        return Calendar.MARCH;

                    case 'y':
                        skipWord();
                        return Calendar.MAY;

                    default:
                        return -1;
                }

            case 'N':
                skipWord();
                return Calendar.NOVEMBER;

            case 'O':
                skipWord();
                return Calendar.OCTOBER;

            case 'S':
                skipWord();
                return Calendar.SEPTEMBER;

            default:
                return -1;
        }
    }
    /**
     * Read until EOF or a space.
     *
     * The input is discarded.
     */
    private  void skipWord() throws IOException {
        int c;

        do {
            c = read(false);
        } while (c != ' ' && c != -1);

        if (c != -1) unread(c);
    }
    /**
     * Read a line (until next ASCII NL or EOF) as a byte array.
     *
     * @param sizeHint an guess on how large the line will be, in bytes.
     */
    private   byte[] readLine(int sizeHint) throws IOException {
        ByteArrayOutputStream ret = new ByteArrayOutputStream(sizeHint);
        int c;

        while ((c = read(false)) != '\n' && c != -1) {
            if (c != '\r')
                ret.write(c);
        }

        return ret.toByteArray();
    }
    private   String readWordString(int sizeHint) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(sizeHint);
        readWord(out);
        this.charset = Charset.forName("UTF8");

        return out.toString(charset.name());
    }
    private   void readWord(OutputStream out) throws IOException {
        int c;

        while ((c = read(false)) != ' ' && c != -1)
            out.write(c);

        if (c != -1) unread(c);
    }
    private   byte[] readWord(int sizeHint) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(sizeHint);
        readWord(out);

        return out.toByteArray();
    }
    private   byte[] readWordOrNil(int sizeHint) throws IOException {
        byte[] ret = readWord(sizeHint);

        if (ret.length == 1 && ret[0] == '-')
            return null;

        return ret;
    }
    /**
     * Read RFC 5424 structured data.
     *
     * Just read the structured data, but don't create a map of it.
     */
    private   byte[] readStructuredData() throws IOException {
        int c = read(true);

        if (c == '-') return null;

        ByteArrayOutputStream ret = new ByteArrayOutputStream(128);

        if (c != '[') throw new IOException("Unexpected syslog character: " + (char) c);

        while (c == '[') {
            ret.write(c);

            // Read SD-ID
            while ((c = read(true)) != ' ' && c != ']')
                ret.write(c);

            ret.write(c);

            while (c == ' ') {
                // Read PARAM-NAME
                while ((c = read(true)) != '=')
                    ret.write(c);

                ret.write(c);

                expect('"');
                ret.write('"');

                // Read PARAM-DATA
                while ((c = read(true)) != '"') {
                    ret.write(c);

                    if (c == '\\') {
                        c = read(true);
                        ret.write(c);
                    }
                }

                ret.write(c);

                c = read(true);
                ret.write(c);
            }

            if (c != ']') throw new IOException("Unexpected syslog character: " + (char) c);

            c = read(true);
        }

        unread(c);

        return ret.toByteArray();
    }
    private   byte[] readTag() throws IOException {
        ByteArrayOutputStream ret = new ByteArrayOutputStream(16);
        int c;

        while ((c = read(true)) != ':' && c != '[' && c != '\r' && c != '\n')
            ret.write(c);

        unread(c);

        return ret.toByteArray();
    }
    private  byte[] readPid() throws IOException {
        ByteArrayOutputStream ret = new ByteArrayOutputStream(8);
        int c;

        expect('[');

        while ((c = read(true)) != ']' && c != '\r' && c != '\n')
            ret.write(c);

        return ret.toByteArray();
    }
    private  Map<String, String>  createEvent(int version, int priority, Calendar date, String hostname, byte[] appname, byte[] procId, byte[] msgId, byte[] structuredData, byte[] body) {
        Map<String, String> fields = new HashMap<String, String>();
        Long looo = date.getTimeInMillis();
        System.out.println("DATE: " + date);
        System.out.println("AMAHOSTA: " + hostname);

        fields.put("DATE",  looo.toString() ) ;///!!hz
        fields.put("HOSTNAME",  hostname ) ;///!!hz

        return fields;
    }

}