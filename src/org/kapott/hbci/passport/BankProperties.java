package org.kapott.hbci.passport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

public class BankProperties {
    private static final int COL_NAME            = 0;
    private static final int COL_SITZ            = 1;
    private static final int COL_BIC             = 2;
    private static final int COL_CRC             = 3;
    private static final int COL_HBCI_HOST       = 4;
    private static final int COL_PIN_TAN_URL     = 5;
    private static final int COL_HBCI_VERSION    = 6;
    private static final int COL_PIN_TAN_VERSION = 7;
    
    private static Properties props = new Properties();
    static {
        try {
            props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("blz.properties"));
        } catch (IOException exc) {
            throw new ExceptionInInitializerError(exc);
        }
    }
    private static long[] allBlz;
    static {
        allBlz = initAllBlz();
    }

    private static String getCol(long blz, int col) {
        String[] split = props.getProperty(""+blz, "").split("\\|");
        if (split != null && split.length > col) {
            return split[col];
        }
        return "";
    }
    
    public static String getName(long blz) {
        return getCol(blz, COL_NAME);
    }
    
    public static String getSitz(long blz) {
        return getCol(blz, COL_SITZ);
    }
    
    public static String getBic(long blz) {
        return getCol(blz, COL_BIC);
    }
    
    public static String getCrc(long blz) {
        return getCol(blz, COL_CRC);
    }
    
    public static String getHbciHost(long blz) {
        return getCol(blz, COL_HBCI_HOST);
    }
    
    public static String getPinTanUrl(long blz) {
        return getCol(blz, COL_PIN_TAN_URL);
    }
    
    public static String getHbciVersion(long blz) {
        return getCol(blz, COL_HBCI_VERSION);
    }
    
    public static String getPinTanVersion(long blz) {
        return getCol(blz, COL_PIN_TAN_VERSION);
    }
    
    public static boolean has8(long blz) {
        return !getCol(blz, 8).isEmpty();
    }

    public static long[] initAllBlz() {
        List<Long> blzKeys = new ArrayList<Long>();
        Iterator<Object> iter = props.keySet().iterator();
        while (iter.hasNext()) {
            Object next = iter.next();
            if (next instanceof String) {
                try {
                    blzKeys.add(Long.valueOf((String)next));
                } catch (Exception exc) {
                    exc.printStackTrace();
                }
            }
        }
        int size = blzKeys.size();
        long[] blzArr = new long[size];
        for (int i = 0; i < size; i++) {
            blzArr[i] = blzKeys.get(i).longValue();
        }
        return blzArr;
    }

    public static long[] getAllBlz() {
        return allBlz;
    }
    
    public static boolean containsBlz(long blz) {
        return props.containsKey(""+blz);
    }
}
