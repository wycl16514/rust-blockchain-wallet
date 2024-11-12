pub mod wallet;
use wallet::Wallet;
pub mod blockchain;
use blockchain::BlockChain;

fn main() {
    let wallet = Wallet::new();
    println!("private key: {}", wallet.private_key_str());
    println!("public key: {}", wallet.public_key_str());
    println!("address: {}", wallet.get_address());

    let transaction = wallet.sign_transaction(&"0x1234567890".to_string(), 100);
    println!("transaction : {:?}", transaction);
    println!("verify: {}", Wallet::verify_transaction(&transaction));

    let wallet_miner = Wallet::new();
    let wallet_a = Wallet::new();
    let wallet_b = Wallet::new();

    let tx_a_b = wallet_a.sign_transaction(&wallet_b.get_address(), 100);
    let mut blockchain = BlockChain::new(wallet_miner.get_address());
    let is_add = blockchain.add_transaction(&tx_a_b);
    println!("Added: {}", is_add);
    blockchain.mining();
    blockchain.print();
    println!("A: {:?}\n", blockchain.calculate_total_amount(wallet_a.get_address()));
    println!("B: {:?}\n", blockchain.calculate_total_amount(wallet_b.get_address()));
    println!("Miner: {:?}\n", blockchain.calculate_total_amount(wallet_miner.get_address()));
}
