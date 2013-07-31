package org.kapott.hbci.passport;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.kapott.hbci.callback.HBCICallback;
import org.kapott.hbci.exceptions.HBCI_Exception;
import org.kapott.hbci.exceptions.InvalidPassphraseException;
import org.kapott.hbci.exceptions.InvalidUserDataException;
import org.kapott.hbci.manager.HBCIUtils;
import org.kapott.hbci.manager.HBCIUtilsInternal;
import org.kapott.hbci.manager.LogFilter;

public class HBCIPassportPinTanStoredPin extends HBCIPassportPinTan {
    public static final String PASSPORT_TYPE = "PinTanStoredPin";
    
    private static final long serialVersionUID = 1L;
    private final static byte[] CIPHER_SALT = { (byte)0x26, (byte)0x19, (byte)0x38, (byte)0xa7, (byte)0x99, (byte)0xbc, (byte)0xf1, (byte)0x55 };
    private final static int    CIPHER_ITERATIONS=987;

    private SecretKey subClassPassportKey;

    public HBCIPassportPinTanStoredPin(Object init,int dummy)
    {
        super(init, dummy);
    }

    public HBCIPassportPinTanStoredPin(Object initObject)
    {
        super(initObject);

        String  header="client.passport.PinTan.";
        String  fname=HBCIUtils.getParam(header+"filename");
        boolean init=HBCIUtils.getParam(header+"init","1").equals("1");
        
        if (fname==null) {
            throw new NullPointerException("client.passport.PinTan.filename must not be null");
        }
        
        HBCIUtils.log("loading passport data from file "+fname,HBCIUtils.LOG_DEBUG);
        setFileName(fname);
        setCertFile(HBCIUtils.getParam(header+"certfile"));
        setCheckCert(HBCIUtils.getParam(header+"checkcert","1").equals("1"));
        
        setProxy(HBCIUtils.getParam(header+"proxy",""));
        setProxyUser(HBCIUtils.getParam(header+"proxyuser",""));
        setProxyPass(HBCIUtils.getParam(header+"proxypass",""));

        if (init) {
            HBCIUtils.log("loading data from file "+fname,HBCIUtils.LOG_DEBUG);
            
            if (!new File(fname).canRead()) {
                HBCIUtils.log("have to create new passport file",HBCIUtils.LOG_WARN);
                askForMissingData(true,true,true,true,true,true,true);
                saveChanges();
            }

            ObjectInputStream o=null;
            try {
                
                if (subClassPassportKey == null) {
                    throw new InvalidPassphraseException();
                }

                PBEParameterSpec paramspec=new PBEParameterSpec(CIPHER_SALT,CIPHER_ITERATIONS);
                Cipher cipher=Cipher.getInstance("PBEWithMD5AndDES");
                cipher.init(Cipher.DECRYPT_MODE, subClassPassportKey, paramspec);
                    
                o=new ObjectInputStream(new CipherInputStream(new FileInputStream(fname),cipher));

                setCountry((String)(o.readObject()));
                setBLZ((String)(o.readObject()));
                setHost((String)(o.readObject()));
                setPort((Integer)(o.readObject()));
                setUserId((String)(o.readObject()));
                setSysId((String)(o.readObject()));
                setBPD((Properties)(o.readObject()));
                setUPD((Properties)(o.readObject()));

                setHBCIVersion((String)o.readObject());
                setCustomerId((String)o.readObject());
                setFilterType((String)o.readObject());
                
                try {
                    setAllowedTwostepMechanisms((List)o.readObject());
                    try {
                        setCurrentTANMethod((String)o.readObject());
                    } catch (Exception e) {
                        HBCIUtils.log("no current secmech found in passport file - automatically upgrading to new file format", HBCIUtils.LOG_WARN);
                        // TODO: remove this
                        HBCIUtils.log("exception while reading current TAN method was:", HBCIUtils.LOG_DEBUG);
                        HBCIUtils.log(HBCIUtils.exception2String(e), HBCIUtils.LOG_DEBUG);
                    }
                } catch (Exception e) {
                    HBCIUtils.log("no list of allowed secmechs found in passport file - automatically upgrading to new file format", HBCIUtils.LOG_WARN);
                    // TODO: remove this
                    HBCIUtils.log("exception while reading list of allowed two step mechs was:", HBCIUtils.LOG_DEBUG);
                    HBCIUtils.log(HBCIUtils.exception2String(e), HBCIUtils.LOG_DEBUG);
                }
                
                try {
                    /*
                     * 2013-07-02 - Schobbert : hier wird nun auch die PIN gelesen, falls sie in die Passportdatei geschrieben wurde!
                     */
                    setPIN((String)o.readObject());
                } catch (Exception exc) {
                    HBCIUtils.log("keine pin...", HBCIUtils.LOG_WARN);
                }
                
                // TODO: hier auch gew�hltes pintan/verfahren lesen
            } catch (Exception e) {
                throw new HBCI_Exception("*** loading of passport file failed",e);
            }

            try {
                o.close();
            } catch (Exception e) {
                HBCIUtils.log(e);
            }
            
            if (askForMissingData(true,true,true,true,true,true,true))
                saveChanges();
        }
    }
    

    @Override
    public void saveChanges()
    {
        // call super.saveChanges() so subClassPassportKey gets initialized!
        // therefore, don't wonder - file will therfore be written twice!
        super.saveChanges();
        
        try {
            PBEParameterSpec paramspec=new PBEParameterSpec(CIPHER_SALT,CIPHER_ITERATIONS);
            Cipher cipher=Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(Cipher.ENCRYPT_MODE, subClassPassportKey, paramspec);

            File passportfile=new File(getFileName());
            File directory=passportfile.getAbsoluteFile().getParentFile();
            String prefix=passportfile.getName()+"_";
            File tempfile=File.createTempFile(prefix,"",directory);

            ObjectOutputStream o=new ObjectOutputStream(new CipherOutputStream(new FileOutputStream(tempfile),cipher));

            o.writeObject(getCountry());
            o.writeObject(getBLZ());
            o.writeObject(getHost());
            o.writeObject(getPort());
            o.writeObject(getUserId());
            o.writeObject(getSysId());
            o.writeObject(getBPD());
            o.writeObject(getUPD());

            o.writeObject(getHBCIVersion());
            o.writeObject(getCustomerId());
            o.writeObject(getFilterType());
            
            // hier auch gewaehltes zweischritt-verfahren abspeichern
            List l=getAllowedTwostepMechanisms();
            // TODO: remove this
            StringBuffer sb=new StringBuffer();
            for (Iterator i=l.iterator(); i.hasNext(); ) {
                sb.append(i.next()+", ");
            }
            HBCIUtils.log("saving two step mechs: "+sb, HBCIUtils.LOG_DEBUG);
            o.writeObject(l);
            
            // TODO: remove this
            String s=getCurrentTANMethod(false);
            HBCIUtils.log("saving current tan method: "+s, HBCIUtils.LOG_DEBUG);
            o.writeObject(s);

            o.writeObject(getPIN());
            
            o.close();
            passportfile.delete();
            tempfile.renameTo(passportfile);
        } catch (Exception e) {
            throw new HBCI_Exception("*** saving of passport file failed",e);
        }
    }
    

    public void askForPin()
    {
        if (getPIN()==null) {
            StringBuffer s=new StringBuffer();

            HBCIUtilsInternal.getCallback().callback(this,
                                             HBCICallback.NEED_PT_PIN,
                                             HBCIUtilsInternal.getLocMsg("CALLB_NEED_PTPIN"),
                                             HBCICallback.TYPE_SECRET,
                                             s);
            if (s.length()==0) {
                throw new HBCI_Exception(HBCIUtilsInternal.getLocMsg("EXCMSG_PINZERO"));
            }
            setPIN(s.toString());
            LogFilter.getInstance().addSecretData(getPIN(),"X",LogFilter.FILTER_SECRETS);
        }
    }
    
    @Override
    protected SecretKey calculatePassportKey(boolean forSaving)
    {
        try {
            StringBuffer passphrase=new StringBuffer();
            HBCIUtilsInternal.getCallback().callback(this,
                                             forSaving?HBCICallback.NEED_PASSPHRASE_SAVE
                                                      :HBCICallback.NEED_PASSPHRASE_LOAD,
                                             forSaving?HBCIUtilsInternal.getLocMsg("CALLB_NEED_PASS_NEW")
                                                      :HBCIUtilsInternal.getLocMsg("CALLB_NEED_PASS"),
                                             HBCICallback.TYPE_SECRET,
                                             passphrase);
            if (passphrase.length()==0) {
                throw new InvalidUserDataException(HBCIUtilsInternal.getLocMsg("EXCMSG_PASSZERO"));
            }
            LogFilter.getInstance().addSecretData(passphrase.toString(),"X",LogFilter.FILTER_SECRETS);

            SecretKeyFactory fac=SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            PBEKeySpec keyspec=new PBEKeySpec(passphrase.toString().toCharArray());
            SecretKey passportKey=fac.generateSecret(keyspec);
            keyspec.clearPassword();

            subClassPassportKey = passportKey;
            return passportKey;
        } catch (Exception ex) {
            throw new HBCI_Exception(HBCIUtilsInternal.getLocMsg("EXCMSG_PASSPORT_KEYCALCERR"),ex);
        }
    }
    
    
}
