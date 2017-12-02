import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import java.io.File;
import java.io.IOException;
import java.util.Scanner;

public class ParseData {
    public static void main(String[] args) throws ParserConfigurationException, SAXException,
            IOException, XPathExpressionException, IllegalArgumentException {
        String text = getData();
        SyslogParser syslogParser = new SyslogParser(text);
        syslogParser.parseWindowsEvent();
       syslogParser.printData();

    }
    private  static String getData()throws ParserConfigurationException, SAXException,
            IOException, XPathExpressionException, IllegalArgumentException{
        Scanner scanner = new Scanner( new File("in.log"), "UTF-8" );
        String text = scanner.useDelimiter("\\A").next();
        return text;
    }
}
