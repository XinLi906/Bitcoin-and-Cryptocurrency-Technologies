import java.security.PublicKey;
import java.util.ArrayList;

public class TxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    private UTXOPool utxoPool;

    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     * values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        ArrayList<Transaction.Input> inputs = tx.getInputs();
        ArrayList<Transaction.Output> outputs = tx.getOutputs();

        double inputVal = 0.0;
        double outputVal = 0.0;

        UTXOPool checkPool = new UTXOPool();

        for (int i = 0; i < inputs.size(); i++) {
            Transaction.Input in = inputs.get(i);
            int index = in.outputIndex;
            byte[] signature = in.signature;

            UTXO u = new UTXO(in.prevTxHash, index);

            if (!utxoPool.contains(u)) {
                return false;
            }

            Transaction.Output out = utxoPool.getTxOutput(u);

            if (checkPool.contains(u)) {
                return false;
            }
            checkPool.addUTXO(u, out);

            byte[] message = tx.getRawDataToSign(i);
            PublicKey address = out.address;

            boolean valid = Crypto.verifySignature(address, message, signature);
            if (!valid) {
                return false;
            }

            double currVal = out.value;
            inputVal += currVal;
        }

        for (Transaction.Output out : outputs) {
            double currVal = out.value;
            if (currVal < 0) {
                return false;
            }
            outputVal += currVal;
        }

        return inputVal >= outputVal;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> validTxs = new ArrayList<>();
        for (Transaction tx : possibleTxs) {
            if (isValidTx(tx)) {
                validTxs.add(tx);

                ArrayList<Transaction.Input> inputs = tx.getInputs();
                for (Transaction.Input in : inputs) {
                    int index = in.outputIndex;
                    byte[] message = in.prevTxHash;

                    UTXO u = new UTXO(message, index);
                    utxoPool.removeUTXO(u);
                }

                ArrayList<Transaction.Output> outputs = tx.getOutputs();
                for (int i = 0; i < outputs.size(); i++) {
                    Transaction.Output out = outputs.get(i);
                    byte[] message = tx.getHash();
                    UTXO u = new UTXO(message, i);
                    utxoPool.addUTXO(u, out);
                }
            }
        }
        Transaction[] a = new Transaction[validTxs.size()];
        return validTxs.toArray(a);
    }

}
