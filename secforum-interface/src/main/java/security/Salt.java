package security;

import java.sql.Timestamp;
import java.util.Comparator;
import java.util.TreeMap;


/**
 * Singleton class responsible to generate salts and save a list of the lasts # generated
 */
public final class Salt {

    private static Salt salt;

    private static int N_SALTS_SAVED = 24;  // saves the last 24 salts generated

    private TreeMap<Timestamp, byte[]> timeSaltMap;
    private DeterministicSecureRandom secureRandom;



    private Salt(){

        this.timeSaltMap = new TreeMap<>(new Comparator<Timestamp>() {
            @Override
            public int compare (Timestamp o1, Timestamp o2) {

                if(o1.after(o2)){ return 1; }

                else if(o1.equals(o2)){ return 0; }

                return -1;
            }
        });

        this.secureRandom = new DeterministicSecureRandom(Hashing_SHA2.generateSalt());

    }



    /**
     * Sets the seed of the salt
     * @param seed Byte array of the seed
     */
    public void setSeed(byte[] seed){

        this.secureRandom = new DeterministicSecureRandom(seed);
        timeSaltMap.clear();
    }



    /**
     * Returns the Salt instance
     * @return Salt instance
     */
    public static Salt getInstance() {

        if (salt == null){
            salt = new Salt();
        }
        return salt;
    }



    /**
     * Generates the new salt
     * @param time Timestamp associated to the salt
     * @return Byte array with the salt
     */
    public byte[] getNewSalt(Timestamp time){

        byte[] array = this.secureRandom.getNext();
        addList(time, array);

        return array;
    }



    /**
     * Returns the treeMap of <Timestamp, salts>
     * @return TreeMap
     */
    public TreeMap<Timestamp, byte[]> getEntries (){

        return this.timeSaltMap;
    }



    /**
     * Returns the last salt used
     * @return Byte array
     */
    public byte[] getLastSalt(){
        if (timeSaltMap.isEmpty()) return null;
        return timeSaltMap.firstEntry().getValue();
    }



    /**
     * Adds a byte array into the list of salts
     * @param time Timestamp associated to each salt
     * @param salt Byte array with the salt
     */
    private void addList(Timestamp time, byte[] salt){

        this.timeSaltMap.put(time, salt);

        // saves the lasts N_SALTS_SAVED salts
        if(this.timeSaltMap.size() > N_SALTS_SAVED){
            this.timeSaltMap.remove(this.timeSaltMap.lastKey());

        }
    }
}
