package main

// mux, letsencrypt, zeit/horoku

import (
    /* Misc */
    "fmt"
    "math"
    "math/big"
    "errors"

    /* RSA + rand */
    "crypto/rand"
    "crypto/rsa"
    "io"

    /* Hash + b58, hex + bytes <-> conversions */
    "bytes"
    "encoding/binary"
    "strconv"
    "encoding/hex"
    "crypto/sha256"
    "golang.org/x/crypto/ripemd160"
    "github.com/akamensky/base58"

    /* Localhost server */
    "net/http"
    "github.com/gorilla/mux"
    "time"
    "log"
)

// MISC Functions
func trip(e error) { // Check for errors
	if e != nil {
		panic(e)
	} else {
        return
    }
}
func stringToByte(str string) []byte { // Convert string to []byte
    return []byte(fmt.Sprintf("%d", str))
}
func intToByte(integer int) []byte { // Convert string to []byte
    return []byte(strconv.Itoa(integer))
}
func stringToHex(str string) int { // I'm not sure this works
    originByte := []byte(str)
	encodeByte := make([]byte, hex.EncodedLen(len(originByte)))
	return hex.Encode(encodeByte, originByte)
}
func byteToHex(inputByte []byte) string {
    encodeByte := make([]byte, hex.EncodedLen(len(inputByte)))
    hex.Encode(encodeByte, inputByte)
    hexString := fmt.Sprintf("%s", encodeByte)
    return hexString
}

// Tx, Block, + Blockchain Structs
type Tx struct {
    Sender string
    Receiver string
    Amount uint
    Memo string
}
type Block struct {
    Txs []Tx
    Hash string
    Nonce int
    MerkleRoot string
    Blockchain *Blockchain
}
type Blockchain struct {
    Chain []Block
    Name string
    CoinName string
    Difficulty int
    Unordered []Tx
    TxMax int
}
type User struct {
    name string
    private *rsa.PrivateKey
    public rsa.PublicKey
    address string
}

// INIT Functionality
func (bc *Blockchain) InitialBlock() {
    var initBlock Block
    initBlock.Txs = []Tx{}
    initBlock.Hash = "0000000000000000000000000000000000000000000000000000000000000000"
    initBlock.MerkleRoot = "0000000000000000000000000000000000000000000000000000000000000000"
    initBlock.Nonce = 0
    initBlock.SetBlockchain(bc)
    bc.Chain = []Block{initBlock}
}

// MINING Functionality (chronologically ordered)
func (b *Block) AddTx(tx... Tx) {
    b.Txs = append(b.Txs, tx...)
}
func (b *Block) SetBlockchain(blockchain *Blockchain) {
    b.Blockchain = blockchain
}
func MakeMerkleRoot(txs []Tx, printStatements... bool) string {
    // Activate or deactivate print statements
    var print bool
    if len(printStatements) != 0 {
        print = printStatements[0]
    }

    // Begin recursive program
    if len(txs) == 0 {
        trip(errors.New("Chief we have a problem."))
    } else if len(txs) == 1 {
        tx := []byte(fmt.Sprintf("%v", txs[0])) // Convert to []byte
        txSha256 := sha256.Sum256(tx) // SHA256
        if print { fmt.Println(byteToHex(txSha256[:])) } // Only print if var is true
        return byteToHex(txSha256[:])
    } else if len(txs) == 2 { 
        zero := stringToByte(MakeMerkleRoot([]Tx{txs[0]})) // Hashed first element
        one := stringToByte(MakeMerkleRoot([]Tx{txs[1]})) // Hashed second element
        both := [][]byte{zero, one} // Both together as an array
        byteBoth := []byte(fmt.Sprintf("%v", both)) // Convert to []byte
        bothSha256 := sha256.Sum256(byteBoth) // SHA256
        if print { fmt.Println(byteToHex(bothSha256[:])) } // Only print if var is true
        return byteToHex(bothSha256[:])
    } else if len(txs) == 3 {
        zeroone := stringToByte(MakeMerkleRoot([]Tx{txs[0], txs[1]},printStatements...)) // Hashed first two elements
        two := stringToByte(MakeMerkleRoot([]Tx{txs[2]},printStatements...)) // Hashed third element
        both := [][]byte{zeroone, two} // Both together as an array
        byteBoth := []byte(fmt.Sprintf("%v", both)) // Convert to []byte
        bothSha256 := sha256.Sum256(byteBoth) // SHA256
        if print { fmt.Println(byteToHex(bothSha256[:])) } // Only print if var is true
        return byteToHex(bothSha256[:])
    } else {
        midpoint := int(math.Round(float64(len(txs)/2)))
        left := stringToByte(MakeMerkleRoot(txs[0:midpoint],printStatements...)) // Hashed left side
        right := stringToByte(MakeMerkleRoot(txs[midpoint:len(txs)],printStatements...)) // Hashed right side
        both := [][]byte{left, right} // Both together as an array
        byteBoth := []byte(fmt.Sprintf("%v", both)) // Convert to []byte
        bothSha256 := sha256.Sum256(byteBoth) // SHA256
        if print { fmt.Println(byteToHex(bothSha256[:])) } // Only print if var is true
        return byteToHex(bothSha256[:])
    }
    return ""
}
func (b *Block) AssignMerkleRoot(printStatements... bool) {
    b.MerkleRoot = MakeMerkleRoot(b.Txs, printStatements...)
}
func FindNonce(prevHash string, merkleRoot string, difficulty int) (int, string) {
    prevByte := stringToByte(prevHash)
    merkleByte := stringToByte(merkleRoot)
    nonce := 0
    for true {
        all := [][]byte{prevByte, merkleByte, intToByte(nonce)} // Both together as an array
        byteAll := []byte(fmt.Sprintf("%v", all)) // Convert to []byte
        allSha256 := sha256.Sum256(byteAll) // SHA256
        hexedShaed := byteToHex(allSha256[:])
        conditional, _ := strconv.ParseInt(hexedShaed[0:difficulty], 16, 64)
        if conditional == 0 {
            return nonce, hexedShaed
        }
        nonce++
    }
    return -1, ""
}
func (bc *Blockchain) getPrevHash() string {
    return bc.Chain[len(bc.Chain)-1].MerkleRoot
}
func (b *Block) AssignHashAndNonse() {
    if b.MerkleRoot != "" {
        b.Nonce, b.Hash = FindNonce(b.Blockchain.getPrevHash(), b.MerkleRoot, b.Blockchain.Difficulty)
    } else {
        trip(errors.New("Merkle Root not defined."))
    }
}
func (bc *Blockchain) AddBlock(block Block) {
    bc.Chain = append(bc.Chain, block)
}
func (bc *Blockchain) AddBlockFromTxList(txs []Tx) {
    if len(txs) <= bc.TxMax {
        var block Block
        block.AddTx(txs...)
        block.SetBlockchain(bc)
        block.AssignMerkleRoot()
        block.AssignHashAndNonse()
        bc.AddBlock(block)
    } else {
        trip(errors.New("Tx list greater than blockchain max block size."))
    }
}

func (bc *Blockchain) GetFunds(address string) uint {
	var funds uint
	for _, block := range bc.Chain {
		for _, tx := range block {
			if tx.sender == address	{
				funds -= tx.amount
			}
			if tx.receiver == address {
				funds += tx.amount
			}
		}
	}
	return funds
}



// PKI & ADDRESS Functionality
func MakePrivatePublicAddress() (*rsa.PrivateKey, rsa.PublicKey, string) {
    ripeHash := ripemd160.New() // Init RIPEMD160 hash
    private, err := rsa.GenerateKey(reader, 256) // Generate private/public, assign private
    trip(err)
    public := private.PublicKey // Assign public
    publicKeyN := []byte(fmt.Sprintf("%d", public.N)) // Extract N and convert to []byte
    sha256N := sha256.Sum256(publicKeyN)
    ripeShaN, err := ripeHash.Write(sha256N[:])
    trip(err)
    ripeShaNB := bytes.NewBuffer([]byte(fmt.Sprintf("%d", ripeShaN))) // Converts []byte to int
    ripeShaInt, err := binary.ReadVarint(ripeShaNB)
    trip(err)
    ripeSha := ripeHash.Sum([]byte(fmt.Sprintf("%d", ripeShaInt)))
    readyToConvert := append([]byte("\x00"), []byte(ripeSha)...)
    b58 := base58.Encode(readyToConvert)
    return private, public, b58
}

// TX Functionality
func (bc *Blockchain) AddToUnordered(tx... Tx) {
    bc.Unordered = append(bc.Unordered, tx...)
}
func (bc *Blockchain) UnorderedToBlock() {
    if len(bc.Unordered) > bc.TxMax {
        bc.AddBlockFromTxList(bc.Unordered[0:bc.TxMax])
        bc.Unordered = bc.Unordered[bc.TxMax:len(bc.Unordered)-1]
    } else {
        bc.AddBlockFromTxList(bc.Unordered)
        bc.Unordered = []Tx{}
    }
}

// PRINT Functionality
func (tx *Tx) Print() {
    fmt.Println("* Tx ...",tx.Sender,"->", tx.Amount, "->",tx.Receiver,"..")//,tx.Memo)
}
func (b *Block) Print() {
    fmt.Println("Merkle Root:",b.MerkleRoot)
    fmt.Println("Nonce:",b.Nonce)
    fmt.Println("Hash:",b.Hash)
    for _, tx := range b.Txs {
        tx.Print()
    }
}
func (bc *Blockchain) Print() {
    fmt.Println("***",bc.Name,"("+bc.CoinName+") ***      ","Difficulty:",bc.Difficulty)
    for id, block := range bc.Chain {
        fmt.Println("** Block",id,"in",bc.Name)
        block.Print()
        fmt.Println()
    }
}

// NETWORK PRINT Functionality
func (tx *Tx) NetPrint(w http.ResponseWriter) {
    fmt.Fprintf(w, "* Tx ... %v -%v-> %v ..\n",tx.Sender, tx.Amount, tx.Receiver)
}
func (b *Block) NetPrint(w http.ResponseWriter) {
    fmt.Fprintf(w, "Merkle Root: %v\n",b.MerkleRoot)
    fmt.Fprintf(w, "Nonce: %v\n", b.Nonce)
    fmt.Fprintf(w, "Hash: %v\n", b.Hash)
    for _, tx := range b.Txs {
        tx.NetPrint(w)
    }
}
func (bc *Blockchain) NetPrint(w http.ResponseWriter) {
    fmt.Fprintf(w, "*** "+bc.Name+" ("+bc.CoinName+") ***      Difficulty: %v\n",bc.Difficulty)
    for id, block := range bc.Chain {
        fmt.Fprintf(w, "\n** Block %v in %s\n", id, bc.Name)
        block.NetPrint(w)
    }
    fmt.Fprintf(w, "\n")
}

// CREATE RANDOM Functionality
func createRandomTx() Tx {
    addresses := [...]string{"Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Thompson", "Garcia", "Martinez", "Robinson", "Clark", "Rodriguez", "Lewis", "Lee", "Walker", "Hall", "Allen", "Young", "Hernandez", "King", "Wright", "Lopez", "Hill", "Scott", "Green", "Adams", "Baker", "Gonzalez", "Nelson", "Carter", "Mitchell", "Perez", "Roberts", "Turner", "Phillips", "Campbell", "Parker", "Evans", "Edwards", "Collins", "Stewart", "Sanchez", "Morris", "Rogers", "Reed", "Cook", "Morgan", "Bell", "Murphy", "Bailey", "Rivera", "Cooper", "Richardson", "Cox", "Howard", "Ward", "Torres", "Peterson", "Gray", "Ramirez", "James", "Watson", "Brooks", "Kelly", "Sanders", "Price", "Bennett", "Wood", "Barnes", "Ross", "Henderson", "Coleman", "Jenkins", "Perry", "Powell", "Long", "Patterson", "Hughes", "Flores", "Washington", "Butler", "Simmons", "Foster", "Gonzales", "Bryant", "Alexander", "Russell", "Griffin", "Diaz", "Hayes"}
    
    // Get rand numbers
    bigArrayLength, _ := rand.Int(reader, big.NewInt(int64(len(addresses))))
    arrayLength := int(bigArrayLength.Int64())
    bigAmountToSendMax, _ := rand.Int(reader, big.NewInt(10))
    amountToSendMax := int(bigAmountToSendMax.Int64())
    
    // Convert to useful values
    sender := addresses[arrayLength]
    receiver := addresses[amountToSendMax]
    amount := uint(bigAmountToSendMax.Int64())

    // Init memo
    memo := "No reason." //"Because "+sender+" felt bad for "+receiver+"."

    return  Tx{Sender: sender, Receiver: receiver, Amount: amount, Memo: memo}
}
func createListTxs(size int) []Tx {
    var txs []Tx
    for i := 0; i < size; i++ {
        txs = append(txs, createRandomTx())
    }
    return txs
}
func createTxUsers() Tx { // Same as createRandomTx but instead of a standard list of names, uses Bitcoin user addresses preivously generated
    // Generate address
    var addresses []string
    for _, user := range Users {
        addresses = append(addresses, user.address+" ["+user.name+"]")
    }
    if len(addresses) == 0 {
        return Tx{Sender: "error: len0"}
    }
    //addresses := [...]string{"Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Thompson", "Garcia", "Martinez", "Robinson", "Clark", "Rodriguez", "Lewis", "Lee", "Walker", "Hall", "Allen", "Young", "Hernandez", "King", "Wright", "Lopez", "Hill", "Scott", "Green", "Adams", "Baker", "Gonzalez", "Nelson", "Carter", "Mitchell", "Perez", "Roberts", "Turner", "Phillips", "Campbell", "Parker", "Evans", "Edwards", "Collins", "Stewart", "Sanchez", "Morris", "Rogers", "Reed", "Cook", "Morgan", "Bell", "Murphy", "Bailey", "Rivera", "Cooper", "Richardson", "Cox", "Howard", "Ward", "Torres", "Peterson", "Gray", "Ramirez", "James", "Watson", "Brooks", "Kelly", "Sanders", "Price", "Bennett", "Wood", "Barnes", "Ross", "Henderson", "Coleman", "Jenkins", "Perry", "Powell", "Long", "Patterson", "Hughes", "Flores", "Washington", "Butler", "Simmons", "Foster", "Gonzales", "Bryant", "Alexander", "Russell", "Griffin", "Diaz", "Hayes"}
    
    // Get rand numbers
    bigArrayLength, _ := rand.Int(reader, big.NewInt(int64(len(addresses))))
    arrayLength := int(bigArrayLength.Int64())
    bigAmountToSendMax, _ := rand.Int(reader, big.NewInt(10))
    amountToSendMax := int(bigAmountToSendMax.Int64())
    
    // Convert to useful values
    sender := addresses[arrayLength]
    receiver := addresses[amountToSendMax]
    amount := uint(bigAmountToSendMax.Int64())

    // Init memo
    memo := "No reason." //"Because "+sender+" felt bad for "+receiver+"."

    return  Tx{Sender: sender, Receiver: receiver, Amount: amount, Memo: memo}
}
func createListTxsUsers(size int) []Tx { // Same as createListTxs but instead of a standard list of names, uses Bitcoin user addresses preivously generated
    var txs []Tx
    for i := 0; i < size; i++ {
        txs = append(txs, createTxUsers())
    }
    return txs
}
func createBlockchain(name string, coinname string, difficulty int, txmax int) Blockchain {
    var blockchain Blockchain
    var initBlock Block
    initBlock.Txs = []Tx{}
    initBlock.Hash = "0000000000000000000000000000000000000000000000000000000000000000"
    initBlock.MerkleRoot = "0000000000000000000000000000000000000000000000000000000000000000"
    initBlock.Nonce = 0
    initBlock.SetBlockchain(&blockchain)
    blockchain.Chain = []Block{initBlock}
    blockchain.Difficulty = difficulty
    blockchain.Name = name
    blockchain.CoinName = coinname
    blockchain.TxMax = txmax
    return blockchain
}
func createBlockAndBlockchain(size int) (Block, Blockchain)  {
    listOfTxs := createListTxs(size)
    var block Block
    block.AddTx(listOfTxs...)
    blockchain := createBlockchain("$uperCoin","$PR", 3, 500)
    block.SetBlockchain(&blockchain)
    return block, blockchain
}
func createBlock(size int, blockchain *Blockchain) Block {
    listOfTxs := createListTxs(size)
    var block Block
    block.AddTx(listOfTxs...)
    block.SetBlockchain(blockchain)
    return block
}
func createUser(nameX string) string {
    privateX, publicX, addressX := MakePrivatePublicAddress()
    Users = append(Users, User{name:nameX, private:privateX, public:publicX, address:addressX})
    return addressX
}

// TEST Functionality
func testMerkleRoot() {
    txs := createListTxs(10)
    root := MakeMerkleRoot(txs)
    fmt.Println(root)
}

// MUX Functionality
func MainPage(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, world!")
}
func ShowBlockchain(w http.ResponseWriter, r *http.Request) {
    TheBlockchain.NetPrint(w)
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
    name := mux.Vars(r)["name"]
    address := createUser(name)
    fmt.Fprintf(w, "User called '%s' created with Bitcoin Address %s", name, address)
}
func CreateUsersEnMasse(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    iter, _ := strconv.Atoi(vars["iterations"])
    names := [...]string{"Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Thompson", "Garcia", "Martinez", "Robinson", "Clark", "Rodriguez", "Lewis", "Lee", "Walker", "Hall", "Allen", "Young", "Hernandez", "King", "Wright", "Lopez", "Hill", "Scott", "Green", "Adams", "Baker", "Gonzalez", "Nelson", "Carter", "Mitchell", "Perez", "Roberts", "Turner", "Phillips", "Campbell", "Parker", "Evans", "Edwards", "Collins", "Stewart", "Sanchez", "Morris", "Rogers", "Reed", "Cook", "Morgan", "Bell", "Murphy", "Bailey", "Rivera", "Cooper", "Richardson", "Cox", "Howard", "Ward", "Torres", "Peterson", "Gray", "Ramirez", "James", "Watson", "Brooks", "Kelly", "Sanders", "Price", "Bennett", "Wood", "Barnes", "Ross", "Henderson", "Coleman", "Jenkins", "Perry", "Powell", "Long", "Patterson", "Hughes", "Flores", "Washington", "Butler", "Simmons", "Foster", "Gonzales", "Bryant", "Alexander", "Russell", "Griffin", "Diaz", "Hayes"}
    for i:=0;i<iter;i++ {
        bigNameID, _ := rand.Int(reader, big.NewInt(int64(len(names))))
        nameID := int(bigNameID.Int64())
        name := names[nameID]
        // name = "Mx. "+name
        address := createUser(name)
        fmt.Fprintf(w, "User called '%s' created with Bitcoin Address %s\n", name, address)
    }
}
/*func CreateUsersEnMasseRandomly(w http.ResponseWriter, r *http.Request) {
    bigIter, _ := rand.Int(reader, big.NewInt(100))
    iter := int(bigIter.Int64())
    names := [...]string{"Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Thompson", "Garcia", "Martinez", "Robinson", "Clark", "Rodriguez", "Lewis", "Lee", "Walker", "Hall", "Allen", "Young", "Hernandez", "King", "Wright", "Lopez", "Hill", "Scott", "Green", "Adams", "Baker", "Gonzalez", "Nelson", "Carter", "Mitchell", "Perez", "Roberts", "Turner", "Phillips", "Campbell", "Parker", "Evans", "Edwards", "Collins", "Stewart", "Sanchez", "Morris", "Rogers", "Reed", "Cook", "Morgan", "Bell", "Murphy", "Bailey", "Rivera", "Cooper", "Richardson", "Cox", "Howard", "Ward", "Torres", "Peterson", "Gray", "Ramirez", "James", "Watson", "Brooks", "Kelly", "Sanders", "Price", "Bennett", "Wood", "Barnes", "Ross", "Henderson", "Coleman", "Jenkins", "Perry", "Powell", "Long", "Patterson", "Hughes", "Flores", "Washington", "Butler", "Simmons", "Foster", "Gonzales", "Bryant", "Alexander", "Russell", "Griffin", "Diaz", "Hayes"}
    for i:=0;i<iter;i++ {
        bigNameID, _ := rand.Int(reader, big.NewInt(int64(len(names))))
        nameID := int(bigNameID.Int64())
        name := names[nameID]
        name = "Mx. "+name
        address := createUser(name)
        fmt.Fprintf(w, "User called '%s' created with Bitcoin Address %s\n", name, address)
    }
}*/
func ListUsers(w http.ResponseWriter, r *http.Request) {
    catch := false
    for _, user := range Users {
        catch = true
        fmt.Fprintf(w, "%v has %v address %v\n", user.name, TheBlockchain.Name, user.address)
    }
    if !catch {
        fmt.Fprintf(w, "No users yet!")
    }
}
func PrintUser(w http.ResponseWriter, r *http.Request) {
    // Iterate through all txs and assess their money count
    requestinput := mux.Vars(r)["user"]
    catch := false
    for _, user := range Users {
        if user.name == requestinput || user.address == requestinput {
            catch = true
            fmt.Fprintf(w, "%v has %v address %v\n", user.name, TheBlockchain.Name, user.address)
        }
    }
    if !catch {
        fmt.Fprintf(w, "Oops! Typo?")
    }
}

func RandomBlock(w http.ResponseWriter, r *http.Request) {
    newTxs := createListTxsUsers(100)
    if len(Users) != 0 {
        TheBlockchain.AddToUnordered(newTxs...)
        fmt.Fprintf(w, "New transactions added to the unordered pile.")
    } else {
        fmt.Fprintf(w, "System failure: you haven't created any users yet!")
    }
}
func FullyRandomBlock(w http.ResponseWriter, r *http.Request) {
    TheBlockchain.AddToUnordered(createListTxs(100)...)
    fmt.Fprintf(w, "New transactions added to the unordered pile.")
}
func AddTx(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    sender := vars["sender"]
    receiver := vars["receiver"]
    signedAmount, _ := strconv.Atoi(vars["amount"])
    amount := uint(signedAmount) // int --> uint
    memo := vars["memo"]
    TheBlockchain.AddToUnordered(Tx{Sender: sender, Receiver: receiver, Amount: amount, Memo: memo} )
    fmt.Fprintf(w, "New transaction added to ordered. ")
}
func MineBlock(w http.ResponseWriter, r *http.Request) {
    TheBlockchain.UnorderedToBlock()
    fmt.Fprintf(w, "New block mined.")
}

func ChangeDifficulty(w http.ResponseWriter, r *http.Request) {
    difficulty, _ := strconv.Atoi(mux.Vars(r)["difficulty"])
    TheBlockchain.Difficulty = difficulty
    fmt.Fprintf(w, "Difficulty changed to %v.", difficulty)
}
func ChangeSize(w http.ResponseWriter, r *http.Request) {
    size, _ := strconv.Atoi(mux.Vars(r)["size"])
    TheBlockchain.TxMax = size
    fmt.Fprintf(w, "Size changed to %v.", size)
}
func SysRestart(w http.ResponseWriter, r *http.Request) {
    TheBlockchain = createBlockchain("Turtle Truth Coin","TTC", 3, 100)
    Users = []User{}
    fmt.Fprintf(w, "System restarted.")
}
func SysRestartSpecifications(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    difficulty, _ := strconv.Atoi(vars["difficulty"])
    size, _ := strconv.Atoi(vars["size"])
    TheBlockchain = createBlockchain(vars["name"],vars["coin"], difficulty, size)
    Users = []User{}
    fmt.Fprintf(w, "System restarted.")
}

// MAIN Functionality

// Create blockchain and list of users
var TheBlockchain Blockchain = createBlockchain("Turtle Truth Coin","TTC", 3, 100)
var Users []User
var reader io.Reader = rand.Reader // Init rand

func main() {
    // Initialise the blockchain
    TheBlockchain.InitialBlock()

    // Create and sustain server
    r := mux.NewRouter()
    r.HandleFunc("/", MainPage)

    r.HandleFunc("/createuser/{name}", CreateUser)
    r.HandleFunc("/createusers/{iterations}", CreateUsersEnMasse)
    // r.HandleFunc("/createusers/", CreateUsersEnMasseRandomly) // Couldn't get
    r.HandleFunc("/users", ListUsers)
    r.HandleFunc("/users/{user}", PrintUser)
    r.HandleFunc("/user/{user}", PrintUser)

    r.HandleFunc("/addrandomblock", RandomBlock)
    r.HandleFunc("/addfullyrandomblock", FullyRandomBlock)
    r.HandleFunc("/addtx/{sender}/{reciever}/{amount}/{memo}", AddTx)
    r.HandleFunc("/addtransaction/{sender}/{reciever}/{amount}/{memo}", AddTx)

    r.HandleFunc("/mine", MineBlock)
    r.HandleFunc("/blockchain", ShowBlockchain)

    r.HandleFunc("/difficulty/{difficulty}", ChangeDifficulty)
    r.HandleFunc("/size/{size}", ChangeSize)
    r.HandleFunc("/restart", SysRestart)
    r.HandleFunc("/restart/{name}/{coin}/{difficulty}/{size}", SysRestartSpecifications)

    s := &http.Server{
        Addr:           ":8080",
        Handler:        r,
        ReadTimeout:    10 * time.Second,
        WriteTimeout:   10 * time.Second,
        MaxHeaderBytes: 1 << 20,
    }
    log.Fatal(s.ListenAndServe())
}
