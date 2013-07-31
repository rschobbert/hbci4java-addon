package org.kapott.hbci.passport;

import java.io.File;
import java.util.Properties;

import org.kapott.hbci.GV.HBCIJob;
import org.kapott.hbci.GV_Result.GVRKUms;
import org.kapott.hbci.callback.HBCICallback;
import org.kapott.hbci.callback.HBCICallbackConsole;
import org.kapott.hbci.manager.HBCIHandler;
import org.kapott.hbci.manager.HBCIUtils;
import org.kapott.hbci.status.HBCIExecStatus;
import org.kapott.hbci.structures.Konto;

public class PassportCreatorFromConsole {
    
    
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            throw new IllegalArgumentException("Usage: "+PassportCreatorFromConsole.class.getSimpleName()+" <BLZ> <KONTONR> <USERID> [<PASSPORT_DIR>]");
        }
        
        long blz = parseAndCheckBlz(args[0]);
        long kontoNr = Long.parseLong(args[1]);
        String userId = args[2];
        File passportDir = args.length > 3 ? new File(args[3]) : new File(".");
        if (!passportDir.exists() && !passportDir.mkdirs()) {
            throw new IllegalArgumentException("Provided passportDir does not exist and cannot be created: "+passportDir.getAbsolutePath());
        } else if (passportDir.isFile()) {
            throw new IllegalArgumentException("Provided passportDir already exists but is a regular file: "+passportDir.getAbsolutePath());
        }
        File passportFile = getPassportFile(passportDir, blz, kontoNr).getCanonicalFile();
        Properties props = new Properties();
        props.put("client.passport.PinTan.filename", passportFile.getAbsolutePath());
        props.put("client.passport.PinTan.checkcert", "1");
        props.put("client.passport.PinTan.init", "1"); // laut Doku muss init immer = 1 sein
        HBCIUtils.init(props, new CreatorCallback(blz, userId));
        
        HBCIPassportPinTanStoredPin passport = createPassport(passportFile);
        usePassport(passport);
    }
    
    private static HBCIPassportPinTanStoredPin createPassport(File passportFile) {
        HBCIPassportPinTanStoredPin passport = (HBCIPassportPinTanStoredPin)AbstractHBCIPassport.getInstance(HBCIPassportPinTanStoredPin.PASSPORT_TYPE);
        if (!passportFile.exists()) {
            System.out.println("Creating passport file: "+passportFile.getAbsolutePath());
            System.out.flush();
            
            passport.askForPin();
            passport.saveChanges();
        }
        return passport;
    }
    
    private static void usePassport(HBCIPassportPinTanStoredPin passport) {
        HBCIHandler  hbciHandle = null;
        
        try {
            // ein HBCI-Handle für einen Nutzer erzeugen
            String passportBlz = passport.getBLZ();
            long blz = Long.parseLong(passportBlz);
            String version = BankProperties.getHbciVersion(blz);
            if (version == null || version.trim().length() == 0) {
                throw new IllegalArgumentException("");
            }
            hbciHandle=new HBCIHandler(version,passport);

            // auszuwertendes Konto automatisch ermitteln (das erste verfügbare HBCI-Konto)
            Konto myaccount=passport.getAccounts()[0];

            // Job zur Abholung der Kontoauszüge erzeugen
            HBCIJob auszug=hbciHandle.newJob("KUmsAll");
            auszug.setParam("my",myaccount);
            auszug.addToQueue();

            // alle Jobs in der Job-Warteschlange ausführen
            HBCIExecStatus ret=hbciHandle.execute();

            GVRKUms result=(GVRKUms)auszug.getJobResult();
            // wenn der Job "Kontoauszüge abholen" erfolgreich ausgeführt wurde
            if (result.isOK()) {
                // kompletten kontoauszug als string ausgeben:
                System.out.println(result.toString());
                
            } else {
                // Fehlermeldungen ausgeben
                System.out.println("Job-Error");
                System.out.println(result.getJobStatus().getErrorString());
                System.out.println("Global Error");
                System.out.println(ret.getErrorString());
            }
        } finally {
            if (hbciHandle!=null) {
                hbciHandle.close();
            } else if (passport!=null) {
                passport.close();
            }
        }
    }
    

    private static File getPassportFile(final File passportDir, final long blz, final long kontoNr) {
        return new File(passportDir, "passport_"+blz+"_"+kontoNr);
    }

    public static long parseAndCheckBlz(String blzString) {
        long blz = Long.parseLong(blzString);
        if (blz < 10000000 && blz > 99999999) {
            throw new IllegalArgumentException("Illegal BLZ: "+blz+", must be >= 10000000 and <= 99999999");
        }
        if (!BankProperties.containsBlz(blz)) {
            throw new IllegalArgumentException("BLZ "+blz+" is not present in blz.properties");
        }
        return blz;
    }

    
    public static class CreatorCallback extends HBCICallbackConsole {
        private String blz;
        private String userId;
        private String customerId;
        
        public CreatorCallback(long blz, String userId) {
            this.blz        = Long.toString(blz);
            this.userId     = userId;
            this.customerId = userId;
        }
        
        public void setCustomerId(String customerId) {
            if (customerId != null) {
                this.customerId = customerId;
            }
        }
        
        private boolean mustAskUser(int reason, int datatype, StringBuffer retData) {
            if (reason == HBCICallback.NEED_CONNECTION || reason == HBCICallback.CLOSE_CONNECTION) {
                return false;
            }
            if (reason == HBCICallback.NEED_COUNTRY || reason == HBCICallback.NEED_HOST || reason == HBCICallback.NEED_PORT || reason == HBCICallback.NEED_FILTER) {
                return retData.length() == 0;
            }
            return true;
        }
        
        @Override
        public void callback(HBCIPassport passport, int reason, String msg, int datatype, StringBuffer retData) {
            if (reason == HBCICallback.NEED_BLZ) {
                retData.replace(0, retData.length(),blz);
                
            } else if (reason == HBCICallback.NEED_USERID) {
                retData.replace(0, retData.length(), userId.trim());
                
            } else if (reason == HBCICallback.NEED_CUSTOMERID) {
                retData.replace(0, retData.length(), customerId.trim());
                
            } else if (mustAskUser(reason, datatype, retData)) {
                super.callback(passport, reason, msg, datatype, retData);
            }
        }
    }
}
