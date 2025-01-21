//
//  Point25519.swift
//  SwiftEd
//
//  Created by Leif Ibsen on 24/04/2020.
//

import BigInt

struct Point25519 {
    
    static let INFINITY = Point25519()
    
    let X: BInt
    let Y: BInt
    let Z: BInt
    let T: BInt
    
    private init() {
        self.init(BInt.ZERO, BInt.ONE, BInt.ONE, BInt.ZERO)
    }

    init(_ x: BInt, _ y: BInt) {
        self.init(x, y, BInt.ONE, Point25519.modP(x * y))
    }

    init(_ X: BInt, _ Y: BInt, _ Z: BInt, _ T: BInt) {
        self.X = X
        self.Y = Y
        self.Z = Z
        self.T = T
    }

    // Reduction modulo Ed25519.P
    static func modP(_ x: BInt) -> BInt {
        return x.isNegative ? Ed25519.P - Ed25519.reduceModP(-x) : Ed25519.reduceModP(x)
    }

    // [RFC-8032] - section 5.1.4
    func add(_ p: Point25519) -> Point25519 {
        let A = Point25519.modP((self.Y - self.X) * (p.Y - p.X))
        let B = Point25519.modP((self.Y + self.X) * (p.Y + p.X))
        let C = Point25519.modP(self.T * p.T * Ed25519.D * 2)
        let D = Point25519.modP(self.Z * p.Z * 2)
        let E = B - A
        let F = D - C
        let G = D + C
        let H = B + A
        return Point25519(Point25519.modP(E * F), Point25519.modP(G * H), Point25519.modP(F * G), Point25519.modP(E * H))
    }

    func double(_ n: Int) -> Point25519 {
        var XX = self.X
        var YY = self.Y
        var ZZ = self.Z
        var TT = self.T
        for _ in 0 ..< n {
            let A = Point25519.modP(XX * XX)
            let B = Point25519.modP(YY * YY)
            let C = Point25519.modP(ZZ * ZZ * 2)
            let H = A + B
            let E = H - Point25519.modP((XX + YY) ** 2)
            let G = A - B
            let F = C + G
            XX = Point25519.modP(E * F)
            YY = Point25519.modP(G * H)
            ZZ = Point25519.modP(F * G)
            TT = Point25519.modP(E * H)
        }
        return Point25519(XX, YY, ZZ, TT)
    }

    func negate() -> Point25519 {
        return Point25519(Ed25519.P - self.X, self.Y, self.Z, Ed25519.P - self.T)
    }

    // [RFC-8032] - section 5.1.2
    func encode() -> Bytes {
        var bytes = Bytes(repeating: 0, count: 32)
        let zInv = self.Z.modInverse(Ed25519.P)
        let x = Point25519.modP(self.X * zInv)
        let y = Point25519.modP(self.Y * zInv)
        var k = 0
        for i in 0 ..< y.magnitude.count {
            var m = y.magnitude[i]
            for _ in 0 ..< 8 {
                bytes[k] = Byte(m & 0xff)
                k += 1
                m >>= 8
            }
        }
        if x.isOdd {
            bytes[31] |= 0x80
        }
        return bytes
    }

    /// Multiplies the current point by a scalar using the double-and-add method.
    /// - Parameter scalar: The scalar value as a `BInt`.
    /// - Returns: The resulting `Point25519` after multiplication.
    func multiply(_ scalar: BInt) -> Point25519 {
        guard scalar > 0 else { print("[Point25519.multiply Error]: scalar is not >0"); return Point25519() }
        var result = Point25519.INFINITY
        var addend = self
        var k = scalar
        while k > 0 {
            if k.isOdd {
                result = result.add(addend)
            }
            addend = addend.double(1)
            k >>= 1
        }
        return result
    }

    // Multiply the generator point
    // [GUIDE] - algorithm 3.41, window width = 4
    static func multiplyG(_ n: Bytes) -> Point25519 {
        var a = Point25519.INFINITY
        var b = Point25519.INFINITY
        for j in (1 ..< 16).reversed() {
            var k = 0
            for i in 0 ..< n.count {
                if n[i] & 0x0f == j {
                    b = b.add(Point25519.gPoints[k])
                }
                if (n[i] >> 4) & 0x0f == j {
                    b = b.add(Point25519.gPoints[k + 1])
                }
                k += 2
            }
            a = a.add(b)
        }
        return a
    }

    // Precomputed multiples of the generator point

    static let gPoints: [Point25519] = [
    Point25519(
         BInt("15112221349535400772501151409588531511454012693041857206046113283949847762202")!,
         BInt("46316835694926478169428394003475163141307993866256225615783033603165251855960")!,
         BInt("1")!,
         BInt("46827403850823179245072216630277197565144205554125654976674165829533817101731")!),
    Point25519(
         BInt("35199924985831822953418105944844487729430054719564991418476909717320259008066")!,
         BInt("50604206233638257853262765357197543899555584215825287093518541626165306404688")!,
         BInt("14912225178663911125783625081420481833941813300289506543592007010319841933954")!,
         BInt("29585892980792193703208899068381067584025858155225566940160030742044451013803")!),
    Point25519(
         BInt("25974847292305168929384928038852351746616499171194102956819510786061956366635")!,
         BInt("11066117818376317936585569391476053575161661237075035045601266614361297547728")!,
         BInt("43235040305884800907062109306515015404167231444826000903245140187832107167338")!,
         BInt("882149493683160284138950403461355846846978596850613808984867398523212753980")!),
    Point25519(
         BInt("48136357915434554704999232690608793003819941025944415056299393394611594431328")!,
         BInt("4497120599594176671929020754225744174143074631914977943946631600588903609750")!,
         BInt("14050527562977561057454498162358119211409201121986671510975546156872591339286")!,
         BInt("48930860386449780985682436944234975255914716690461898652229545341989794765217")!),
    Point25519(
         BInt("4890982659421744994305547397334906956131897611274677694626663101633264398383")!,
         BInt("45878116663421351005142889088442808847365508224243183769970010834936674800676")!,
         BInt("42153767725646820241641781857991354869636610399855573478181046254387470620466")!,
         BInt("44665821771527389611459359200297519821683732275612645792314731928653229571407")!),
    Point25519(
         BInt("5966350275126058066229030379708257547460040372568974834034722385519088668576")!,
         BInt("28113380908031092605942401387537913399476862786749912386295852275447823510413")!,
         BInt("27754408015273814186413940054193397804901440130920126417101603165767496424012")!,
         BInt("29403879126315573566962408077495233305767527387459063464097985812791676600553")!),
    Point25519(
         BInt("16866147698568355532325503609195933797139805998972503629817590423941819092779")!,
         BInt("41586770113074178390381793901636497809521846013076408143688605486750182216070")!,
         BInt("39444293862579509787747374304524597440019468671056529127679666711574761046575")!,
         BInt("10801930749190586833282101903717886292335731148778720137237472304616600168939")!),
    Point25519(
         BInt("19891512023267707195897910242990110294559084387806998392832663402345308618866")!,
         BInt("43344714725732052205989642542325245993371976224071267102961275245482936486182")!,
         BInt("43822428813502470377709057227106346170556105993548853341152132755281886842586")!,
         BInt("20394214428331699961565215802901459761923766373485433231418336805772679135186")!),
    Point25519(
         BInt("40289608090405564541477922590801720196825525211440107065193110118248554496188")!,
         BInt("45754512552714673841525655584040573383839888356291183844408592177725921563515")!,
         BInt("54045168936250773740758874732916371286432654483203972713789777725129225549338")!,
         BInt("2053866297011402975034439438639354421967334357739931984962535042970988485661")!),
    Point25519(
         BInt("47742281467024319745976156199266940929336563701263854360825724777946093949796")!,
         BInt("43150843771778149096815901695099972207934204767832278181847133000562536823416")!,
         BInt("2692154561198242562525413755866794928429659970816801630495140579956611509311")!,
         BInt("24754472704145219935227629543593624894648812939458889043124900740358458599471")!),
    Point25519(
         BInt("36958966036774891035490815831006470585286345844729181927885005905265928351597")!,
         BInt("32754346335574112670735383163940045353971725434251264505738995058056623632397")!,
         BInt("31424489234733092093090797126684777885802592194672518864322053907221969377926")!,
         BInt("49406427795340437333484676931817888169818484468993405951895551174369729597128")!),
    Point25519(
         BInt("1681355004416363396194369909551392251615020851333058171686397203945174961322")!,
         BInt("50307045822620258130183219925590785208643026572939624529078189731671491165051")!,
         BInt("4104121594085874668551278518735721573467214875101081890440351660018161332401")!,
         BInt("44609177245203515631849201424072184393072263234896754821178247193434842890812")!),
    Point25519(
         BInt("24941610704469908564266667551658667672410653354388325958822786826116403562663")!,
         BInt("45817410447373984294383533507636581878879387740719707238893007581252133498545")!,
         BInt("24385541334024920149854793682897764127355120802572380827176155373203638013290")!,
         BInt("32298039452744529579975892023108465636070303806960603455895045881032678502819")!),
    Point25519(
         BInt("49253697300348073340184392891089563258717516370486145939003028538227722635867")!,
         BInt("54070767125253326629740582995408684953621807027388186887940694936282892335620")!,
         BInt("22150332366814153691137049278850867860332299836916425464289917298644223591666")!,
         BInt("7926435786868410653276899613720759623001244484633438371561377827088732569577")!),
    Point25519(
         BInt("28154342575827646389730845424743258711294886563239248559394168828883990569167")!,
         BInt("10224446487738934452401015938820735586704504558681831225379605175690081023103")!,
         BInt("57233510841453582623126869534235264992787464210736957024556169387749330717948")!,
         BInt("50310298927473850579174340832254053881287811586020913706129893745658066276386")!),
    Point25519(
         BInt("33956347150585532526447313652733488197104297799493841087487484210182408104754")!,
         BInt("40628320172306025415699743295141332257069872029434747619659291367136295574922")!,
         BInt("16640384675939562143523365517340844887670951567049803796182621747133829295653")!,
         BInt("29899921484303594995326834155571702748369474855020513826249945009557948022191")!),
    Point25519(
         BInt("40952604817188496919157402946062861175059685875060705260801628629240451559693")!,
         BInt("12132699588792979764961583222177067164402681708333041124048671211262474272627")!,
         BInt("29989825879010373401175515094141830976459470340848478560069067940083827738080")!,
         BInt("53324871565251107436106996769257834121610009454574808694602878383227039389062")!),
    Point25519(
         BInt("30091988875360484152416155391368238928827641516789978815351335369201913589135")!,
         BInt("47442278049194968015692508997313182463413079863655662018353735226774743769425")!,
         BInt("12181368177654942948469283313849376417520771684991480615011857771135150451447")!,
         BInt("36838140158124013321078299151817787954600832538252831237101673145319173440669")!),
    Point25519(
         BInt("15693629152384528485688245317680524724311443940205082368458776612428098740092")!,
         BInt("13492740738550666024654915309070746169637740382669822826863372352761976638760")!,
         BInt("6305749482159116630961451728256431693553258070649054976087860078229040093223")!,
         BInt("16937341148732131274617063107661970300347354610355756979871436141506915717766")!),
    Point25519(
         BInt("14336495892944303035094971843307549097487344597756553585548612948890424995691")!,
         BInt("40379878813819750989960137888558662934988122996077839523202695553791938768072")!,
         BInt("16263522776695195960367213576726259038409690102153806388959501393269474818921")!,
         BInt("10723853670346041113664418806467842308069706828002623565706078165963911379946")!),
    Point25519(
         BInt("44749905799798778407576794984716063532598828427571596186621624367787684918568")!,
         BInt("21262897179355102627463127317964281103062886845974103282085794826612922713633")!,
         BInt("4909027737168102862316629467373123106173680981924212315091851690221636126775")!,
         BInt("56264889657409368187728454940127408438047535784260958130021765564220797696859")!),
    Point25519(
         BInt("27567678596602164669187938041273547878621628227215632133379652917584840358038")!,
         BInt("20156788419270250593813626975313709583280878776657504153390076320645871909850")!,
         BInt("865287151190091763753097124165448722342880934536858113924860196536240024115")!,
         BInt("44989293611645588263830618243357971890191723272239165901742948406216764047370")!),
    Point25519(
         BInt("6652083576228841845135007726786375348112728640959100912134199371653247352807")!,
         BInt("23926366837205782651315335124726775030368019169472563495183456410592023423476")!,
         BInt("3186073461185249761287763574717497940388448237431474462059185260194753957356")!,
         BInt("55738632840603854237368661879006402769673168110861483921681343458783328315400")!),
    Point25519(
         BInt("19695896325095091943763534505095940216408128578650685017319059935942295014798")!,
         BInt("10328210463204280654099787306024149366940568427982392693737523744224297744723")!,
         BInt("14723275283118884209624514884830777354678262987471681326592937786646381885279")!,
         BInt("31914668585265894655957915099188878807076283471457035110977346972598256474676")!),
    Point25519(
         BInt("45974239331013596003514362904544155971315957059625135734944406068463031329375")!,
         BInt("43584441715104588317180681904573393766320663898673250220614986616721258562743")!,
         BInt("1360933901721024415982712274303620472904647406286605490265108295497437148868")!,
         BInt("19610035244114204947383729633385225708178458223616060821032390151718922993362")!),
    Point25519(
         BInt("39461335694924456214270509376018165136554038778488120245467241578856872242880")!,
         BInt("12867984628500922333947023586575466194314613125256064941904905658833426744474")!,
         BInt("42500841127657377833421614592610513451907388068671485318520411368214612008629")!,
         BInt("52620483512246280373489767447727735296477330561917405625884033428595381488187")!),
    Point25519(
         BInt("35577186196613056051594558575457061237878326781886516600784838536733174465932")!,
         BInt("9182487700011681276344631361753788007775752583678866854374491399177928180751")!,
         BInt("30212360176326376705037619051777730266903032955377715840780140816882552150225")!,
         BInt("41751533704295451773951436010093187958241966836259371954434576724249505171086")!),
    Point25519(
         BInt("49345547102508708490145702947057017814980378689560815974768948738287170163792")!,
         BInt("6253188053879124821620016956673497634001604542175014694329432809197351055001")!,
         BInt("51637693066868381605210769103241783512918415611761055710687612894523735171033")!,
         BInt("47969987713590731229283595268562515267603947619524906431989270424232077288754")!),
    Point25519(
         BInt("733539915389797448354532398238704631212921037267618536259100688746360001047")!,
         BInt("13273281488662562455142030836688219776666448489582603049531115059155106832754")!,
         BInt("16266857313691498251682050142743195413219199729014192749053326386187575469293")!,
         BInt("31843180722115131874291773591996344643781937161997834062403147223420115282033")!),
    Point25519(
         BInt("5473696151242497441864171444198634883867195753007877466474794336020571109850")!,
         BInt("11967558234000622355903550241754946034278787214379302807710144009280185118138")!,
         BInt("3139781545514125587034799017195616460233006180658319462041738478475378336510")!,
         BInt("34155682566148807223979221942104612574968423588008548818483890441230209462364")!),
    Point25519(
         BInt("43780294667150179862874875338623993661509736829793963382666708074498428882787")!,
         BInt("25213188489919916603817046406301262991606593760677445181231873130911197567051")!,
         BInt("27757817254226481841871562329427409936588693342906692945657709985320166058154")!,
         BInt("15543094823420803752506698088760461918805590299321637658669579361435151752013")!),
    Point25519(
         BInt("10808289353449731789419274383447228577850257122103223937499942843676982729780")!,
         BInt("7059710302135435399834139685488129168664652259847694395091807836891405126953")!,
         BInt("47815168252206024760050432331224278747291683614675629730918456781765247453935")!,
         BInt("37937295249242496226918014760389574852145212408724767343676751166579126188158")!),
    Point25519(
         BInt("25482491596146113109675137322459739760296918450676765339369182699307007505022")!,
         BInt("4791466155490694555397274907975505969562820400435558422128877461368201883260")!,
         BInt("54661932726140717567050830555856219252620078061165898756480945084430415119680")!,
         BInt("27938876836402838712207177680998979385053916553232345040765568647362893421277")!),
    Point25519(
         BInt("43108201340432523686637950558146838932315680394531142844946874055809306650871")!,
         BInt("15049909506415287333417503394422421200948462199679960842350535116942492466221")!,
         BInt("40092802505882730284016355319651898557563516638020232102644524574473625144174")!,
         BInt("35326691566105732756431014956425654059437886796571856570681494930947799608423")!),
    Point25519(
         BInt("11523542781511512321257713263420715428136528461616890371505555598606942818101")!,
         BInt("40920062309099910015113848525509410777502991251334452506631334237834023672615")!,
         BInt("50051876509971265252702672716009840049373286495699630024648515872839091257446")!,
         BInt("51386703927575610832727534795032693923074167675942985610618372542417997856393")!),
    Point25519(
         BInt("19135694648954982785295262043317729366413173985569814740957527582956029164350")!,
         BInt("16985715640949493916088083819458725303650590553268064234878589772244401528758")!,
         BInt("11888687797178062274977164025022896942512456525433448359905206582515494600698")!,
         BInt("52134143092189475079914309932699213479691377071731260992893196158500604078173")!),
    Point25519(
         BInt("7607308965879228264299211195171786540433685241066213005101207092796652207370")!,
         BInt("46306627296745437318429328297372336180186758686471370695487300221061842481543")!,
         BInt("12375414563398367691727743329290993822591748696833633064297532762884838404323")!,
         BInt("47101914169272756714536434671914762350978953521974707940308441703247042821298")!),
    Point25519(
         BInt("15275284823900247778430642158234215424299305247413848470961643227857998487848")!,
         BInt("9401553496621582767767317575458273335802213970522448093560188051351867671940")!,
         BInt("13540778524375834576424083633409292671706521522277532677938513966592392959573")!,
         BInt("46833186052401684851740398765550213942348566424187204705354823221790704794030")!),
    Point25519(
         BInt("49790275156755792354498613313294315470282585254836483736255941330957705753100")!,
         BInt("14501075843095401450469293913847955154071754340287211560649427542635017378985")!,
         BInt("14375965027481803622537685424681481507234929194226861126813432087749341367570")!,
         BInt("8336587760708249481174413380802687389041420059033290904280649275036322064323")!),
    Point25519(
         BInt("51513683724743037627289110844457854285888499362488757785631686431920843572820")!,
         BInt("14545516304283212238093211182664673885358069457091519243972218160533689857348")!,
         BInt("50679442609779070849530043854813847995094807085315612147498523004486397496328")!,
         BInt("49689590537977510027729082782638426125236398419923277492933171519073198969604")!),
    Point25519(
         BInt("17669233095549269439957896747521983047743150053427925076479686623286220104011")!,
         BInt("49330630014394258626358279387369299907218056112238610875904113287002668134738")!,
         BInt("45946211117670946657576901506685634656599614771605294432933638429984499377695")!,
         BInt("6328775829442808155546085717882239175165500780068738815475272828604932718864")!),
    Point25519(
         BInt("3127991049229054561060262287648281417482244933841866098537645148411815475157")!,
         BInt("13176793561785390832491917735612307188892087020915455258304697831586737068375")!,
         BInt("48602478169525979738659837717342777152258780917324866850197770876715586700380")!,
         BInt("15207871153844011201792855976517241077726836005752258178360656921510150004134")!),
    Point25519(
         BInt("33739898476493480687297182986496026584581355217672861912239819607769315725981")!,
         BInt("24925377668906318810017537404411502235182188284839456924047154223904295002042")!,
         BInt("24265610491609876046766221791383579444075021485844016549836635219192116697395")!,
         BInt("7064623591327029419540386077586595922407660569901465735798135310491794823023")!),
    Point25519(
         BInt("6471592986488458275477772260887039488042080381046012367519040887880113769309")!,
         BInt("53724399318483862305971403008778908101547963889674474401703854672677726272459")!,
         BInt("24252331083556614415728355807146539236882610210009828423732094381608843834538")!,
         BInt("43186969671972647809669492061162626172785877251457535412002196454209507559898")!),
    Point25519(
         BInt("15788166001456754433940703239509572220762427430642665994452393051940426573491")!,
         BInt("21518326754364469214276349099883172253613151997171687678066752562282425999932")!,
         BInt("16467392151767378696090073971087579385149669033859977087119887447223933319756")!,
         BInt("10369353484547061856420541598400399381565859049717638526496402238885919526681")!),
    Point25519(
         BInt("18227850507230577147001711636495121693433385797360544562351822133987884677855")!,
         BInt("37851044619879389334825014894705142378620802168886154052336623893795889164017")!,
         BInt("4999432841901303928700452761636955081312491534033038227353941705019445257681")!,
         BInt("51268989448694267954912937747406952956488364318140643287091406358591255025746")!),
    Point25519(
         BInt("4250065329281787206023372021244847508877971022870917800810418691073109320837")!,
         BInt("14560867718936999691549379766916864014525838833353607787757939200190561802136")!,
         BInt("16643270098240312285863115644279366396314921780135958276795893315044426011467")!,
         BInt("3716180450341696553642909679718306881537546081008624298017884689580895508415")!),
    Point25519(
         BInt("41316136147105702373264242210989764063383656496402260789256643958787436536278")!,
         BInt("43608379561769559187084020853463183026538011004170009818916941327245584048298")!,
         BInt("29537482817111768623105301428226536303054133421900976045797497847820491370513")!,
         BInt("12022925177259382354318144662510508386081977574555728576647750491097942136031")!),
    Point25519(
         BInt("40542862488920911184067052833117397474562811775316816774519061644819389987453")!,
         BInt("4163213058244692926642564272126136860298299533676375196728666995406983727469")!,
         BInt("56544409270733709679170597275188728438763683484344233034862317556515452743675")!,
         BInt("34222288992487176398039504739709583142077522914063074593353870113689664572929")!),
    Point25519(
         BInt("48457366487403498330807550591016492162512477444082410406449315323636605808349")!,
         BInt("45089710523813615987658488613315278758173661715586316537893568766251346514653")!,
         BInt("47446445662454308634664548552406148520790791410346799111105971333749018904310")!,
         BInt("46633169822646066770798300264046262614941467850004920045791043740497370848214")!),
    Point25519(
         BInt("39600343449502537927598838301706277336425193279326378903910954466053506903747")!,
         BInt("37077321954730327160453099932989233528698005296391644661056916077901178577530")!,
         BInt("22503030835956593552163966863871999082856593446073143477907204748286561527539")!,
         BInt("18737014813969682269016890898105795488095372423935177937395583379222925493363")!),
    Point25519(
         BInt("34883878198995312579641676485237296839885489947948862128946688535241148179037")!,
         BInt("48043321189670966531306666271692143738411883085846703821971136342444542046174")!,
         BInt("46334916174393584018254080665440889940079446932527805523516197056951179171114")!,
         BInt("4260417929190394519092087995216981361918715418978063213731967080634453520444")!),
    Point25519(
         BInt("15753439642802284344461404142892620284933047728016656886706294833122309132428")!,
         BInt("47352779248657282140440173666832879403842022726911146009424788911616244439758")!,
         BInt("55510654173213352295125178080731422258999924862267916841732535774757690029793")!,
         BInt("50588449374738131768809784088308649068469269723553311289895471833880804252649")!),
    Point25519(
         BInt("42742363628936728917046798404144938302335727244001629602805766104134460449415")!,
         BInt("31098450036749854492012056165704023572327989056048448982746684416113673388175")!,
         BInt("22073000677888834496990622871584378764158541307042986124985818734296995311109")!,
         BInt("19472981914441339691420785541880555644686211575354315480806192477873850038905")!),
    Point25519(
         BInt("613628836460918308896068332188979690013083530749951601293364931451962797812")!,
         BInt("53986223781389181128684963001077550483780419953806081626304548716471684296805")!,
         BInt("25173904253785651586730696879183204040131490345728111370815010820292349376355")!,
         BInt("49642750902790047492819996814030016523469451204207991885522713039299942028092")!),
    Point25519(
         BInt("10428559116372086270795836913090526229979520177590290682842785400578335613882")!,
         BInt("3730264754637108289964330473825794732517440707993690312991556911096875544466")!,
         BInt("39803991362203878218243636571047103822232999499184003040864455115370652210679")!,
         BInt("7610912480522274659870191819149717522079432631256311869259465806280151878877")!),
    Point25519(
         BInt("57085538266495027057460028523516488558759216105824343293755195545110587216678")!,
         BInt("38160376119738541834791009380878348441555055200643930509676908305716537204597")!,
         BInt("25009789428635205930144908298343435785353966888616104666098951990519006613808")!,
         BInt("18444628918339557463539194388100300642964891064297999159079349799653551427898")!),
    Point25519(
         BInt("23025070749638042111514409697085736856614507977681756982921366955299651962794")!,
         BInt("7220456800230904497818822665564253673406568525230149746988395514521424682492")!,
         BInt("12767819582541069977655564012134311074626318086238419050160390107845440345762")!,
         BInt("7807676695816310278196068903093571868791736381521546066356095361015390272799")!),
    Point25519(
         BInt("24392871974411584123068885084656593218930795582169416029884290234661653786924")!,
         BInt("34566470869505846335258379574505065801042308222128305947495449049431341142685")!,
         BInt("1482583819892696317979155239435001666110574357711839125809460458851740372102")!,
         BInt("51250646042975151981212332028258601061284737628596662515072797647778469043184")!),
    Point25519(
         BInt("27367739722661629752895093230206640607159726408598170853419776182123284448676")!,
         BInt("42803408607690679777414614781935195549139956046202024046961214224402642502676")!,
         BInt("37062475235402988917155424629422001160455500025577967740555078560303029621986")!,
         BInt("41571149575110271837506707841879954161005578412644265805245416556651992436690")!),
    Point25519(
         BInt("26274836717811959282516123225506823562451209573196640222887598205641936185657")!,
         BInt("13691537034372081989050047709897128321328565040912419454949746110420809765625")!,
         BInt("56254982380945064631164017467292547378238943203919578296597907238127665914819")!,
         BInt("11065246402992829358847145298015222907879484748939342092565698545781607749735")!),
    Point25519(
         BInt("1681175227235862819262291936231130353672819183080515102065935943199058140723")!,
         BInt("46514491092192033494915280815809334568762834351285015900197238557537979663563")!,
         BInt("56651477705825358085640900406667568835258578541272061990908432550747263436528")!,
         BInt("1739022796467863138198912775074313094982607743000586173598735215195249449965")!),
    Point25519(
         BInt("53974208986202143082532129319159668618515874933364222297836908174173826168196")!,
         BInt("5787855676201440390558623928132846354050327914068972684323892520955455358118")!,
         BInt("31883727992192443631801493942592657589081019353998601088586392805197468174030")!,
         BInt("16251950045791290836684395969158287521617065556895260081398673306757583795355")!),
    Point25519(
         BInt("25021559814070813314322495196878193792878179996701580501747651294151201798988")!,
         BInt("33549120055745894487606319846917215412628346675064755774637079041362698471765")!,
         BInt("43239963945206851056281868827025368349878139130396140876057987723896368329941")!,
         BInt("40750673133812945212194724909452835380225648702710735743614755965618472149896")!),
    ]

}
