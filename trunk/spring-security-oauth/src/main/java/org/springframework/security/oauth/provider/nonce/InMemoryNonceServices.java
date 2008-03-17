package org.springframework.security.oauth.provider.nonce;

import org.acegisecurity.AuthenticationException;
import org.springframework.security.oauth.provider.ConsumerDetails;

import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.*;

/**
 * Expands on the {@link org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices} to
 * include validation of the nonce for replay protection.<br/><br/>
 *
 * To validate of the nonce, the InMemoryNonceService first validates the consumer key and timestamp as does the
 * {@link org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices}.  Assuming the consumer
 * and timestamp are valid, the InMemoryNonceServices further ensures that the specified nonce was not used with the
 * specified timestamp within the specified validity window.  The list of nonces used within the validity window
 * is kept in memory.<br/><br/>
 *
 * @author Ryan Heaton
 */
public class InMemoryNonceServices extends ExpiringTimestampNonceServices {

  protected static final ConcurrentMap<String, LinkedList<TimestampEntry>> TIMESTAMP_ENTRIES = new ConcurrentHashMap<String, LinkedList<TimestampEntry>>();

  @Override
  public boolean validateNonce(ConsumerDetails consumerDetails, long timestamp, String nonce) throws AuthenticationException {
    final long cutoff = (System.currentTimeMillis() / 1000) - getValidityWindowSeconds();
    super.validateNonce(consumerDetails, timestamp, nonce);

    String consumerKey = consumerDetails.getConsumerKey();
    LinkedList<TimestampEntry> entries = TIMESTAMP_ENTRIES.get(consumerKey);
    if (entries == null) {
      entries = new LinkedList<TimestampEntry>();
      TIMESTAMP_ENTRIES.put(consumerKey, entries);
    }

    synchronized (entries) {
      if (entries.isEmpty()) {
        entries.add(new TimestampEntry(timestamp, nonce));
        return true;
      }
      else {
        boolean isNew = entries.getLast().getTimestamp() < timestamp;
        ListIterator<TimestampEntry> listIterator = entries.listIterator();
        while (listIterator.hasNext()) {
          TimestampEntry entry = listIterator.next();
          if (entry.getTimestamp() < cutoff) {
            listIterator.remove();
            isNew = !listIterator.hasNext();
          }
          else if (isNew) {
            //optimize for a new, latest timestamp
            entries.addLast(new TimestampEntry(timestamp, nonce));
            return true;
          }
          else if (entry.getTimestamp() == timestamp) {
            if (!entry.addNonce(nonce)) {
              throw new NonceAlreadyUsedException("Nonce already used: " + nonce);
            }
            return false;
          }
          else if (entry.getTimestamp() > timestamp) {
            //insert a new entry just before this one.
            entries.add(listIterator.previousIndex(), new TimestampEntry(timestamp, nonce));
            return true;
          }
        }

        //got through the whole list; assume it's just a new one.
        //this shouldn't happen because of the optimization above.
        entries.addLast(new TimestampEntry(timestamp, nonce));
        return true;
      }
    }
  }

  protected static class TimestampEntry {

    private final Long timestamp;
    private final Set<String> nonces = new HashSet<String>();

    public TimestampEntry(long timestamp, String firstNonce) {
      this.timestamp = timestamp;
      this.nonces.add(firstNonce);
    }

    /**
     * Adds a nonce to this timestamp entry.
     *
     * @param nonce The nonce to add.
     * @return The nonce.
     */
    public boolean addNonce(String nonce) {
      synchronized (nonces) {
        return nonces.add(nonce);
      }
    }

    /**
     * Get the timestamp for this entry.
     *
     * @return The timestamp for this entry.
     */
    public Long getTimestamp() {
      return timestamp;
    }

    @Override
    public int hashCode() {
      return timestamp.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      return obj instanceof TimestampEntry && this.timestamp.equals(((TimestampEntry) obj).timestamp);
    }
  }
}
