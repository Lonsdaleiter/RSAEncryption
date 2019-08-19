package encryption;

/**
 * An exception thrown by the program when
 * bad things are done.
 *
 * @author Lonsdaleiter
 * */
public class EncryptionException extends Exception {

    private String message;

    public EncryptionException(String message){
        this.message = message;
    }

    public String getMessage(){
        return message;
    }

}
