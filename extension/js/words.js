// Warp Gate gate codes: eight words drawn uniformly from a fixed 7776-word list.
//
// A gate code is what a person reads out, types on a phone keyboard, or pastes into a
// chat. It replaced a 26-symbol base32 string because that string was accurate and
// unusable. Eight words out of 7776 is log2(7776) * 8 = 103.40 bits of entropy, which is
// less than the 128 bits the base32 code carried, and crypto.js buys the difference back
// with 600,000 rounds of PBKDF2 between the code and the room secret S. See crypto.js
// deriveSecret and DESIGN.md 3.2 for that arithmetic; this file only deals in words.
//
// ---------------------------------------------------------------- list provenance
//
// The EFF long list is the obvious choice and is public domain, but it could not be
// obtained: this machine has no network route (curl to eff.org times out with 000), no
// package manager by project policy, no /usr/share/dict/words, and neither aspell nor
// hunspell has a dictionary installed. So the list is DERIVED, deterministically, from
// the only real English dictionary present on the machine: the spell file Vim ships.
//
//   1. Dump Vim's English spell file to text, using Vim's own decoder:
//        script -qec "vim -c 'set spell spelllang=en' -c 'spelldump' \
//                         -c 'w! vim-spelldump.txt' -c 'qa!'" /dev/null
//      Source file: /usr/share/vim/vim92/spell/en.utf-8.spl, 174807 lines dumped.
//   2. Keep lines matching /^[a-z]{4,7}(\/[0-9]+)?$/. Lowercase a-z only, so no
//      apostrophes, no proper nouns, no accents. Four letters minimum because the
//      list guarantees a unique four-character prefix. Seven letters MAXIMUM because
//      the QR encoder in qr.js stops at version 6 (106 payload bytes) and eight
//      nine-letter words plus the origin would overflow it: at seven the worst case
//      is "https://warpgate.fysh.site/app#WARP-" + 8*7 + 7 separators = 99 bytes.
//   3. Drop the whole four-character prefix group of any denied stem: profanity,
//      slurs, and words about death, disease or violence. Group-wise and not
//      word-wise, because a dictionary carries every inflection and denying "murder"
//      alone leaves "murders", "murdered" and "murderer" behind. "warp" is denied
//      too, so the display prefix can never also be a code word.
//   4. Group by the first four characters and keep ONE word per group, ranked:
//      all-region beats region-specific, then shorter, then alphabetical. A trailing
//      "/digits" in the dump means the word is valid in only some of the five English
//      regions the file declares (us, au, ca, gb, nz), which is the colour/color trap:
//      two people would spell it two ways. 8694 groups survive.
//   5. Take the first 7776 by the same ranking, then sort alphabetically. Index order
//      is part of the format, so the sort is what pins index -> word.
//
// The builder is tools-free and reproducible; it lives with this change's notes rather
// than in the repo, because the list is now DATA and must never be regenerated in place:
// a regenerated list with one word moved is a different encoding and would silently
// resolve every existing code to a different secret. WORDLIST_SHA256 below exists to
// make that drift loud, and tests/crypto.test.mjs recomputes it.
//
// Properties, all asserted by tests/crypto.test.mjs:
//   - exactly 7776 entries, all unique
//   - every entry is 4 to 7 lowercase ASCII letters
//   - the first four characters are unique across the list, so a four-character
//     autocomplete is unambiguous and no word is a prefix of any other word
//   - sorted, so the index of a word is stable and findable
//
// ---------------------------------------------------------------- the code format
//
//   displayed as  WARP-CANYON-MARBLE-...        capitals, hyphen separated, one token
//   parsed from   any case, any mix of spaces, hyphens, newlines, with or without the
//                 WARP prefix, and out of a whole link (the part after the first '#')
//   hashed as     "canyon marble ..."           lowercase, single spaces, no prefix
//
// The hashed form is deliberately NOT the displayed form. Display is a presentation
// choice that may change; the bytes that go into PBKDF2 may not, or every existing code
// resolves to a different secret.

const WORDLIST = `
aargh aback abaft abalone abandon abase abate abbey abbot abbrev abdomen abeam
abed abet abhor abide ability abject abjure ablate able abloom ably aboard
abode abolish about above abrade abreast abridge abroad abrupt abscess abseil absorb
abstain absurd abut abuzz abyss acacia academe accede acclaim accord accrue accuse
aced acerbic aces acetic ache achier achoo achy acid acing acme acne
acolyte aconite acorn acquit acre acrid across acrylic acted acting actor actress
acts actual acuity acumen acute adage adamant adapt addable added addle address
adds adduce adenine adept adhere adieu adios adipose adjoin adjure adland adman
admen admit adnate adobe adopt adore adrenal adrift adroit adsorb adult advance
advent advice adware adze adzing aegis aeon aerate aerie aerobic aether afar
affair affect affix afflict afford affray afghan afield afire aflame afloat afoot
afore afoul afraid afresh afro after again agape agar agate agave aged
ageism ageless agent ages aggro aghast agile aging agitate agleam aglow agni
agog agouti agree aground ague ahas ahchoo ahead ahem ahoy aide aidful
aiding aids aikido ailed ailing ailment ails aimed aiming aimless aims ainhum
airbase aircrew aired airfare airgun airhead airier airless airman airplay airs airtime
airway airy aisle aitch ajar akas akimbo akin alack alarm alas alba
albeit albino albs album alchemy alcove alder alee alembic aleph alert ales
alewife alfalfa alga algebra alias alibi alien align alike aliment alive aliyah
alkali alkene alkyd allay alley allied allot alls allude ally almanac almond
alms alnico aloe aloft aloha alone aloof aloud alpaca alpha alpine alps
already alright also altar alter alto alts alum always amalgam amass amateur
amaze amber ambit amble ambush amen amerce amiable amid amigo amino amiss
amity ammeter ammo amnesia amnion amoeba amok among amoral amour ampere amphora
amping ample amps amuck amulet amuse amylase anagram anarchy anatomy anchor ancient
andante anded andiron android ands anemone anent anew angel angina angle angora
angry angst anguish aniline animal anion anise ankh ankle annals annex annoy
annul anode anoint anomaly anon anorak another anoxia answer antacid ante anti
antler antonym antra ants anuran anvil anxiety anybody anyhow anyone anyway aorist
aorta apace apart apathy aped apelike apeman aper apes apex aphasia aphelia
aphid apiary apical apiece aping apish aplenty aplomb apnoea apogee apology apostle
apparel appeal apple appoint apprise apps apricot apron apse apsis apter aptly
aptness aqua aqueous aquifer arable arbiter arbor arbutus arcade arced arch arcing
arcs ardent ardor arduous area arena ares argent argon argue argy aria
arid aright arise arith arks armada armband armed armful armhole armies armlet
armor armpit armrest arms army aroma arose around arras arrest arrive arrow
artery artful artier artless arts artwork arty arum arvo aryl asana asap
ascend ascot ascribe aseptic asexual ashamed ashen ashier ashlar ashore ashram ashtray
ashy aside asinine askance asked asking asks aslant asleep asocial aspen aspic
asps asses assign assort assume aster asthma astir astound astral astute asunder
asylum atavism ataxia atelier ates atheism athirst athlete athwart atilt atlas atoll
atom atone atop atria atrophy attend attic attract attune atty auburn auction
audax audio auger aught augment augur auks aunt aura aureole auricle aurora
auspice austere author autism autumn auxin avail avant avarice avast avatar avaunt
avdp avenge aver aves avgas avian avid avionic avocado avoid avouch avow
await awake award awash away awed aweigh awes awful awhile awing awks
awkward awls awned awning awns awoke awry axed axes axial axil axing
axiom axis axle axolotl axon ayah ayes azalea azimuth azure baaed baaing
baas babble babe babied baboon baby baccy bach bacilli back bacon baddie
bade badge badly badness baffle bagel bagful baggy bagpipe bags bahs baht
bail bairn bait baize bake baking baklava balance balboa balcony bald bale
baling balk balm baloney balsa balun bamboo banal band bane bang banish
banjo bank banns banquet bans bantam banyan banzai baobab baps baptism barb
bard bare barf barge barhop baring bark barley barman barn baron barque
barred bars barter baryon basal base bash basic bask bass batch bate
bath batik batman baton bats batty bauble baud baulk bauxite bawd bawl
bayed baying bayou bays bazaar bazooka beach bead beagle beak beam bean
bear beast beat beau beaver bebop becalm beck becloud become bedaub bedbug
bedded bedeck bedim bedlam bedpan bedrock beds bedtime beech beef beehive beeline
been beep beer bees beet beeves befall befell befit befog began beget
beggar begin begot begrime begs begum behalf behind behold beige being bejewel
belay belch belfry belie bell below belt beluga belying beman bemire bemoan
bemuse bench bend beneath benign bent benumb benzene bequest berate berg berk
berm berry berserk berth beryl beset beside besmear besom bespeak best beta
betel bethink betide betook betray bets better between bevel bevies bevvy bevy
bewail bewitch beyond beys bezel bhaji bias bible bibs biceps bicker bicycle
biddy bide biding bids bier biff bifid bifocal bigamy bigger bight bigness
bigot bigs bigwig bijou bike biking bilby bile bilge bilious bilk bill
bimbo binary bind binge binned bins biog biology biomass bionic biopic bios
biotin biped biplane bipolar birch bird biretta birth biscuit bisect bishop bismuth
bison bisque bistro bite biting bitmap bits bitty bitumen bivalve bivouac bizarre
blab black blade blag blah blame bland blare blast blatant blaze bleak
bled blemish blend bless blew blight blimp blind blip bliss blitz bloat
blob bloc blog bloke blond blossom blot blouse blow blubber blue bluff
bluing blunt blur blush boar boas boat bobby bobcat bobs bobtail bocce
bock bode bodge bodice bodkin bods body boffin boga bogey boggy bogie
bogon bogs bogus boil boing bokeh bola bold bole bolster bolt bolus
bonanza bonbon bonce bond bonfire bong bonier bonkers bonny bonsai bonus bony
boodle booed boogie boohoo booing book boom boon boor boos boot booze
bopped bops borax border bore boring born boron borrow borscht borzoi bosh
bosom boss bosun botany botch both bots bottle boudoir bough boulder bound
bouquet bourbon bout bovine bowed bowing bowl bowman bows boxcar boxed boxier
boxlike boxwood boxy boycott boyer boyhood boyish boys bozo brace brad brae
brag braid brake bramble bran bras brat brave brawl bray braze bread
bred breed breve brew briar bribe brick bride brief brig brill brim
brine brioche brisk brittle broad brocade brogue broil broke bromide bronco brood
brose broth brought brow brunt brush brute bubble bubo bubs buck bucolic
buddy budge budo buds buff bugaboo bugbear bugle bugs build bulb bulge
bulimia bulk bulrush bulwark bumble bumf bummed bump bums bunch bundle bung
bunion bunk bunny buns bunt buoy burble burden bureau burg burka burl
burp burqa burr burs bury busby buses bush busied busk buss bust
busy butane butch butler buts butyl buxom buyback buyer buying buyout buys
buzz byers byes bygone bylaw bypass byplay byre byroad byssi byte byway
byword cabal cabbage caber cabin cable cabs cacao cache cackle cacti caddie
cadet cadge cadmium cadre cads caducei caeca caesura cafe caff caftan cage
cagier cagoule cahoot cairn caisson caitiff cajole cake caking calcify caldera calf
calico calk call calm caloric calumet calve calyx camber came camp cams
canal candy cane canine canker canoe cans cant canvas canyon capable cape
capital capo capped caprice caps carat carbon card care cargo caries cark
carload carmine carnal carob carp carry cars cart carve casaba cascade case
cash casing cassia cast catalpa catbird catch cater catfish catgut cathode cation
catkin catlike catnap cats catty catwalk caucus caudal caught caulk cause caution
cavalry cave cavil cavort cawed cawing caws cayenne cays cease ceca cecum
cedar cede ceding ceilidh celery cell cement censer cent ceramic cereal cerise
cermet certain cervix cession chad chafe chagrin chain chalk champ chant chaos
chap char chase chat cheap check cheddar cheek chef chemise chert chess
chevron chew chge chic chide chief chiffon chigger child chime chin chip
chirp chisel chit chive chloral chock choir chomp choose chop chord chose
choux chow chrism chrome chub chuck chuffed chug chukka chum chunk churl
chute chyme ciao cicada cider cigar cigs cilia cinch cinder cine cipher
circa cirque cirri cissy cistern citadel cite cities citric city civet civic
civvies clack clad claim clam clan clap claque claret clash clatter clause
clavier claw clay clean clef clement clench clerk clever clew click client
cliff climb cling clip clique cloak clobber clock clod clog clomp clone
clop close clot cloud clove clown cloy club cluck clue cluing clump
clung cluster clutch coach coal coarse coast coat coax cobalt cobble coble
cobra cobs cobweb coca cocci cochlea coco coda coddle code codfish codger
codify codon cods coed coequal coerce coeval coexist cogent cognac cogs cohabit
coheir cohort coif coil coin coir coke coking cola cold coleus colic
collar cols colt column comb come comfy comic comma comp comrade conch
cone confab conga conic conjoin conk conman conned conquer cons contd convex
cony cooed cooing cook cool coon coop coos coot copay cope copied
copped copra cops copter copula copy coral corbel cord core corf corgi
coring cork corm corn corona corral corset cortex coses cosh cosine cosmic
cosset cost cosy cote cots cotter couch cough could count coup court
cousin couture cove coward cowboy cowed cowgirl cowherd cowing cowl cowman cowpox
cowries cows coxcomb coxed coxing coyer coyly coyness coyote coypu coys cozen
cozy crab crack cradle craft crag cram crane crash crate crave craw
crayon craze creak credo creed creoles crepe cress cretin crevice crew crib
crick cried crime cringe crisp critic croak crock croft crone crook crop
croquet cross crotch croup crow crucial crud cruel cruft cruise crumb crunch
crupper crura crutch crux crying crypt crystal cube cubic cuboid cubs cuckoo
cuddle cudgel cuds cued cues cuff cuing cuisine cull culprit cult culvert
cumber cumin cums cumuli cunning cupcake cupful cupid cupola cupped cupric cups
curacy curb curd cure curfew curia curl curry curs curt curve cushy
cusp cuss custom cutaway cutback cute cuticle cutler cuts cutter cutup cutworm
cyber cycad cycle cyder cygnet cymbal cynic cypress cyst czarism dabbed dabs
dace dacha dactyl daddy dado dads daemon daffy daft dago dags dahlia
daily dainty dairy dais dale dally damage dame dammed damp dams dance
dandy danger dank dapper dare daring dark darling darn dart dash data
date dating dato datum daub daunt dauphin davit dawdle dawn dayan daybed
days daytime daze dazing dazzle dded dding deacon deaf deal dean dear
debar debit debouch debris debs debt debug decide deck declaim decry deduce
deed deejay deem deep deer deface defied deflate defog defray deft defuse
defy degas degree deice deify deign deism deity deja deject delay delete
delft dell delouse delta delude delve demand demise demur dengue denim denote
dens dent denude deny depart depend depict deploy depot depth depute derail
derby deride dermal derrick dervish desalt descry desert design desk dessert detach
deter detour detract deuce devalue develop device devoid devs dewar dewclaw dewdrop
dewed dewier dewlap dews dewy dexes dhoti dhow diadem diagram dial diamond
diaper diatom dibble dibs dice dicier dicot dicta diddle dido didst diem
diet differ digest digger digit dignify digraph digs dike diktat dilate dilemma
dill dilute dime dimity dimly dimmed dimness dimple dims dimwit dinar dine
ding dining dinky dinned dins dint diocese diode diorama dioxin diploid dipole
dippy dips diptych dire dirge dirk dirndl dirt disarm disbar disc disdain
disgust dish disk dislike disown dispel disrobe disuse ditch dither ditsy ditto
ditz diurnal diva dive divide divot divulge divvy divx dizzy doable dobbin
dobra dobs docile dock docs doctor docx dodder dodge dodo doer does
doff doge dogfish doggy dogie dogleg dogma dogs dogtrot dogwood doily doing
dojo dole doling doll dolmen dolor dolphin dolt domain dome doming donate
done dong donkey donned donor dons doodle doom door dopa dope dopier
dories dork dorm dorsal dory dosage dosh dosing doss dost dotage dote
doth doting dots dotty doubt douche dough dour douse dove dowager dowdy
dowel down dowry dowse doyen doze dozing dozy drab drachma draft drag
drain drake dram drank drape drastic drat draw dray dread dreck dredge
dregs drench dress drew dribble dried drift drill drink drip drive drizzle
drogue droid droll drone drool drop dross drought drove drub drudge druid
drum drupe dryad dryer drying dryly dryness drys drywall dual dubbed dubiety
dubs ducal duchy duck duct dude dudgeon duds duel duenna dues duet
duff dugout dugs duke dulcet dull duly dumb dumdum dummy dump dunce
dune dung dunk dunno duns duodena duopoly duos dupe duping duple durable
duress during durst durum dusk dust dutch duteous duties duty duvet duxes
dwarf dweeb dwell dwindle dyadic dyed dyeing dyer dyes dynamo dyne each
eager eagle earache eardrum eared earful earl earmark earn earplug earring ears
earth earwax ease easier east easy eaten eating eats eave ebbed ebbing
ebbs ebony eccl echelon echo eclat eclipse eclogue ecocide ecology economy ecru
ecstasy ecus eczema eddied eddy edema edge edgier edgy edible edict edify
edit educe eels eely eerie efface effect effigy effort effs effuse egad
eggcup egged egghead egging eggnog eggs egoism egos egotism egret eider eight
either eject eked ekes eking eland elapse elastic elate elbow elder elegy
element eleven elfin elicit elide elision elite elixir elks ellipse ells elms
elodea elope else elude elusive elute elvan elver email emanate embed emblem
embody embryo emcee emend emetic emfs eminent emir emit emmet emoji emos
emote empathy emperor empire employ empower empress empty emulate emus enable enact
enamel encamp enchain enclave encode encrust encyst ended endgame ending endless endmost
endow ends endue endways enema energy enfold engage engine engorge engram engulf
enhance enigma enjoy enlarge enlist enmesh enmity ennoble ennui enough enrage enrich
enrol ensign enslave ensnare ensue entail enter enthuse entice entomb entry entwine
envelop envied envoy envy enzyme eons epee epic epigram episode epitaph epoch
epoxy epsilon equal equerry equip eras erbium eremite ergo ergs ermine erode
erosion errand erred erring error errs ersatz erst eruct erudite erupt escape
eschew escort escrow escudo espied espouse esprit espy esquire essay essence estate
ester estuary etas etch eternal ethane ether ethic ethnic ethos ethyl etude
euchre eugenic eulogy eunuch euphony eureka euro evacuee evade evasion even ever
eves evident evil evince evoke evolve ewer ewes exact exalt exam excel
excise exclaim excreta excuse exempt exert exes exeunt exhale exhibit exhort exigent
exile exist exit exodus exotic expand expel expo express expunge extant extend
extinct extol extra exude exult exurb eyeball eyed eyeful eyeing eyelet eyer
eyes eyewash eyres fable fabric fabs face facial fact faculty faddish fade
fading fado fads faerie faff fagged fagot fags fail fain fair faith
fajitas fake fakir falcon fall false falter fame famous fanatic fancy fanfare
fang fans fantail fanzine farad farce fare farina farm faro farrago fascia
fashion fast fate father fatigue fatly fatness fats fatty fatuity fatwa fault
faun fauvism faux fave favor fawn faxed faxing fayer fayre fays faze
fazing fealty feast feat febrile fecal feces fecund federal fedora feds feeble
feed feel fees feet feign feint feisty feline felon felt female femme
femoral femur fence fend fennel fens feral ferment fern ferox ferry fertile
ferule fervid fess festal feta fetch fete fetlock fetter fetus feud fewer
fewness feyer fiasco fiat fibbed fiber fibril fibs fibula fiche fickle fiction
ficus fiddle fidget fief field fiend fiery fiesta fife fifth figgy fight
figment figs figure filbert filch file filial fill film filo filth final
finch find fine finger finis fink finny fins fiord fire firing firm
firs firth fiscal fish fissile fist fitful fitly fitness fits fitted five
fixate fixed fixing fixture fizz fjord flab flack flag flail flak flame
flan flap flare flash flat flaunt flaw flax flay flea fleck fled
flee flesh flew flex flick flies flight flimsy fling flip flirt flit
float flock floe flood flop flora floss flotsam flour flow flub flue
fluff fluid fluke flume flung flurry flush flute flux flyable flyby flyer
flying flyleaf flyover flypast foal foam fobbed fobs focal foci focus fodder
foes fogey foggy foghorn fogs fogy fohn foible foil foist fold folio
folk folly foment fond font food fool foot foppery fops foray forbid
force ford fore forfeit forge fork forlorn form forsake fort forum forward
fossil foster fought foul found four fovea fowl foxed foxhole foxier foxtrot
foxy foyer fragile frail frame franc frap frat fraud fray frazzle freak
freckle free freight frenzy freon freq fresh fret friar fridge fried frig
frill fringe frisk fritter frizz frock frog froid frolic from frond frost
froth frown froze frugal fruit frump frustum fryer frying fuchsia fuddle fudge
fuel fugal fuggy fugue fulcrum full fulsome fumble fume fumier fums fumy
fund funfair fungi funk funny furbish furies furl furnace furor furry furs
further fury furze fuse fusing fuss fusty futile futon future futz fuzz
gabby gable gabs gadded gadfly gadget gads gaff gaga gage gagged gags
gaiety gaily gain gait gala gale galoot gals galumph gambit game gamin
gamma gamut gamy gander ganja gannet gantry gaol gape gaping gaps garage
garb garden gargle garish garlic garment garner garret gars garter gasbag gases
gasket gasohol gasp gastric gate gather gating gator gauche gaudy gauge gaunt
gauss gauze gave gavotte gawd gawk gawp gayer gayness gays gaze gazing
gear gecko geed geeing geek gees geezer geisha geld gelid gelled gels
gemmy gems gender gene genned genre gens gent genus geode geog geoid
geology geom gerbil germ gerund gesso gestalt getaway gets getting getup gewgaw
geyser ghastly ghat ghee gherkin ghost ghoul giant gibber gibe giblets giddy
gift gigged gigolo gigs gild gilet gill gilt gimbals gimlet gimmick gimp
ginger ginkgo ginned gins gipsy giraffe gird girl giro girt gismo gist
gite gits give giving gizmo gizzard glacial glad glamour gland glare glass
glaze gleam glee glen glib glide glimmer glint glisten glitz gloat glob
gloms gloom glop glory gloss glottal glove glow glucose glue gluier glum
gluon glut glyph gmail gnarl gnash gnat gnaw gneiss gnome gnus goad
goal goat gobbed goblet gobs godhead godly gods goer goes gofer goggle
going gold golf golly gonad gondola gone gong gonk gonna gonzo good
gooey goof googly gooier gook goon goop goose gopher gore gorge gorier
gorp gorse gory gosh gosling gospel gossip goth gotten gouge goulash gourd
gout govern gown grab grace grade graft grail gram grand grape grasp
grate gray graze great grebe greed gremlin grep grew grey grid griffin
grill grim grin griot grip grist grit grizzle groan grocer grog groin
grok grommet groom grope gross grotto group grove grow grub grudge gruel
gruff grump grunt guano guard guava guess guff guide guild guinea guise
guitar gulag gulch gulden gulf gull gulp gumboil gumdrop gummy gums gunge
gunk gunny gunwale gunya guppy gurgle guru gush gusset gust gutless guts
gutted guvs guyed guying guys guzzle gybe gymnast gyms gypped gyps gyrate
gyro gyve gzip habit hack haddock hades hadst haem hafnium haft haggis
hags hahnium haiku hail hair hajj haka hake halal halberd halcyon hale
half haling hall halo halt halve halyard hames hamlet hammy hamper hams
hank hansom hapless happy haps harass hard hare haring hark harlot harm
harness harp harrow harsh hart harvest hash hasp hassle hast hatch hate
hath hating hats hatted hauberk haughty haul haunt hauteur have having havoc
hawed hawing hawk haws haycock hayed haying hayloft haymow hayrick hays haywire
haze hazier hazy head heal heap heat heave hebe heck hectic hedge
heed heehaw heel heft hegira heifer height heinous heir heist held helix
helm helot help helve heme hemline hemmed hemp hems hence henge henna
henpeck henry hens heparin herald herb herd here hermit hernia hero herring
hers hertz hewed hewing hewn hews hexagon hexed hexing heyday hgwy hiatus
hiccup hicks hidden hide hiding hied hieing hies high hike hiking hill
hilt himself hind hinge hint hipbone hippo hips hire hiring hirsute hiss
hist hitch hither hits hitter hive hiving hiya hoard hoax hobby hobnob
hobo hobs hock hocus hodge hods hoecake hoed hoeing hoer hoes hogan
hogback hogged hogs hogwash hoick hoist hoity hoke hoki hokum hold hole
holier holly holmium holster holy homage homburg home hone honing honor hons
hooch hood hooey hoof hook hoon hoop hooray hoot hooves hope hoping
hopped hops hora horde horizon hormone horrid horse hosanna hose hosier hotbed
hotcake hotel hotfoot hothead hotly hotness hotpot hots hotted hough hound hour
house hove howbeit howdah however howl hows hoyden hubby hubcaps hubris hubs
huddle hued hues huff huge hugged hugs huhs hula hulk hull human
humble humdrum humeri humid hummed humor hump hums humus hunch hundred hunk
hunt hurdle hurl hurry hurt husband hush husk hussy hustle hutch huts
hwyl hybrid hydra hyena hygiene hying hymen hymn hype hyphen hyping hypo
hyrax hyssop iamb ibex ibid ibis icebox icecap iced iceman ices icicle
icier icily icing ickier icky icon ictus idea idem ides idiom idle
idling idly idol idyll iffier iffy igloo igneous ignite ignore iguana ilea
ileitis ileum ilia ilium ilks illegal illicit ills illus illy image imam
imbibe imbue imitate immense immoral immune impel impish imply import impress imps
impugn inane inapt inborn inbred inbuilt inch incise incline income incs incur
index indict indoor induce indwell inept inert inexact infamy infix inflow info
infra infuse ingest ingot ingrain inhale inhere inhibit inhuman initial inject inkblot
inked inkier inkling inks inkwell inky inlay inlet inly inmate inmost innate
inner innings inns input inquest inroad inrush inset inshore inside insole inspect
instep insult intact inter into intro intuit inure invent invite invoke inward
ioctl iodide ional ionic ions iota ipecac ippon ipso irate ired ireful
irenic ires iridium iring iris irked irking irks iron irrupt island isle
isms isobar isomer isotope issue isthmus italic itch item iterate itself ivied
ivory jabbed jabot jabs jack jade jaffa jagged jags jaguar jail jalopy
jamb jammed jams jangle janitor japan jape japing jarful jargon jarred jars
jasmine jasper jato jaunt java javelin jawbone jawed jawing jaws jaybird jays
jaywalk jazz jealous jeans jeep jeer jeez jejuna jell jemmy jenny jerry
jersey jess jest jets jetty jewel jibbed jibe jibs jiff jigged jigs
jilt jimmied jingle jink jinn jinx jitsu jitters jive jiving jobbed jobless
jobs jock jocose jocund joey jogged jogs john join joist joke joking
joky jolly jolt jong jonquil josh joss jostle jots jotted joule jounce
journal joust jovial jowl joyed joyful joying joyless joyous joyride joys jubilee
judder judge judo jugged jugs jugular juice jujitsu jujube jukebox julep jumbo
jump junco jungle junior junk junta juries juror jury just jute juts
jutted kabob kabuki kaka kale kana kanji kaolin kaon kapok kappa kaput
karate karma kart katydid kauri kayak kayo kazoo kbyte kcal kebab keel
keen keep kegs kelp kendo kenned keno kens kepi kept keratin kerb
kernel kestrel ketch kettle keyed keyhole keying keynote keypad keys keyword khaki
khan kibble kibosh kick kiddo kids kike kiln kilo kilt kimono kind
kine king kink kinship kiosk kipped kips kiri kirk kirsch kismet kiss
kitchen kite kith kits kitty kiwi klaxon kludge kluge klutz knack knave
knead knee knell knew knick knight knish knit knives knock knoll knot
know knuckle knurl koala koan kobo kohl kola kooky kopeck korma koru
kosher kowtow kraal kraft kraut krill krona krypton kudos kudzu kuku kumquat
kung kyle kylie kyudo label labor labs lace lacier lack laconic lacquer
lacs lactic lacuna lacy ladder lade ladies ladle lads lady lager lagged
lagoon lags laid lain lair laity lake lama lamb lame lamina lammed
lamp lams lanai lance land lane languid lank lanolin lantern lanyard lapdog
lapel lapin lapped laps laptop lapwing larch lard large lariat lark larva
larynx lase lasing lass last latch late lath latish latrine lats latte
laud laugh launch laurel lava lave laving lavs lawful lawless lawn laws
lawyer laxer laxity laxly laxness layer laying layman layout lays layup laze
lazier lazy leach lead leaf league leak lean leap learn leas leather
leave lecher lectern ledge leech leek leer lees leeway left legal legend
leggy leghorn legit legless legman legroom legs legume legwork leis lemma lemon
lemur lend length lenient lens lent leonine leopard leotard lepta lerp lesbian
less lest lets letter letup level levied levy lewd lewis lexer lexical
liable liaise liana liar libel libido library libs lice lichen licit lick
lidded lidless lido lids lied lief liege lien lies lieu life lift
ligate light lignite like liking lilac lilies lilly lilo lilt lily limb
lime limit limn limo limp limy linage linden line ling lining link
linnet lino linseed lint lion lipid lippy lips liquid lira lire lisle
lisp list litany literal lithe litmus litotes litre litter liturgy live livid
lizard llama llano load loaf loam loan loaves lobar lobby lobe lobs
local loch loci lock loco locus lode lodge loft logbook loge logged
logic logjam logo logs logy loin loiter loll lone long loofah look
loom loon loop loose loot lope loping lopped lops lord lore loris
lorn lorry lose losing loss lost lotion lots lotto lotus loud lough
lounge loupe lour louse lout lovable love loving lowbrow lowed lowing lowly
lowness lows loyal lozenge luau lubber lube lubra lucid luck lucre ludic
ludo luff luge lugged lugs lull lulu lumbar lumen lump lunch lune
lung lupine lupus lurch lure lurgy lurid lurk lush lute luxe luxury
lyceum lying lymph lynx lyre lyric lytic mace macho mack macro macs
madam madcap madden made madly madman madras mads maestro mafia magenta maggot
magi magma magnet magpie mags magus mahatma mahout maid mail main maize
majesty major make making male mall malt mama mamba mammy mams manage
mandala mane manful mange manhole mania mankind manly manna manor manse manta
manual many maple mapped maps maraca marble march mare margin marina mark
marl marmot maroon marque marry marsh mart marvel masc maser mash mask
mason masque matador match mate maths mating matrix mats matte mature matzo
maudlin maul maunder mauve maven mawed mawkish maws maxed maxi maybe mayday
mayfly mayhem mayor maypole mayst maze mazurka mazy mdse mead meal mean
meat mecca medal meddle media medley medulla meed meek meet mega megs
meiosis melange meld melee mellow melon melt member memento memo mend menfolk
menial menorah menu meow mercy mere merge merit mermaid merry mers mesa
mescal mesh meson mess mestizo meta mete method metier metro mettle mewed
mewing mewl mews mezzo miasma mica mice mick micro mics middy midge
midi midland midmost midrib midst midterm midway midyear mien miff might mikados
mike miking milady milch mild mile milf milieu milk mill mils milt
mime mimic mimosa minaret mince mind mine mingle mini mink minnow minor
mins mint minus minx mirage mire mirier mirror mirth miry miscue misdeal
miser misfit mishap mislay misname misplay misread miss mist misuse mite mitoses
mitre mitt mixable mixed mixing mixture mizzen moan moat mobbed mobile mobs
mocha mock modal mode modify mods module moggy mogul mohair moiety moil
moire moist molar mold mole moll molten moment momma moms monarch money
monger monies monk mono monsoon month mooch mood mooed mooing moon moor
moos moot mope moping mopped mops mopy moral mordant more morn morrow
morsel mosaic mosey mosh mosque moss most mote moth motif motley motor
mots motto moue mould mound mouse mouth movable move moving mowed mowing
mown mows moxie mtge much muck mucous mucus muddy mudflat mudroom muds
muesli muezzin mufti muggy mugs mulatto mulch mule mulish mull multi mumble
mummy mumps mums munch mundane mung muon mural murk murmur murrain muscle
muse mush music musk muslin mussel must mutant mute mutt mutual muumuu
muzak muzzle myna myopia myriad myrrh myrtle myself mystic myth naan nabbed
nabob nabs nacelle nacho nacre nadir naff nagged nags naiad naif nail
naive naked namby name naming nanny nano napalm nape naphtha napkin napless
nappy naps narc nark narrow narwhal nary nasal nascent nasty natal natch
nation natty nature naught naval nave navies navvy navy nays neap near
neat nebula neck nectar need neep negate neglect negro neigh neither nelson
nemeses neon nephew nerd nerve nest netball nether nets netted network neural
neuter never nevi nevus newbie newel newly newness news newt next nexus
niacin nibble nibs nice niche nick niece niff nifty nigh nilly nimbi
nine ninja ninny ninth niobium nips nirvana nisei niter nitid nitpick nitrate
nits nitwit nixed noble nobody nobs nock nodal noddy node nods nodule
noel noes noggin nohow noir noise nomad nominal nonce none nongs nonplus
noob noodle nook noon nope norm north nose nosh nosier nostril nosy
notary notch note nothing notice nots nougat noun nourish nous nova novel
novice noway nowhere nowt noxious nozzle nroff nuance nubby nubile nubs nuclei
nudge nugget nuking null numb numeral nuncio nunnery nuns nuptial nurse nurture
nutmeg nutria nutty nuzzle nylon nymph oafish oafs oaken oaks oakum oared
oarlock oars oases oasis oatcake oaten oath oatmeal oats obelisk obey obis
obit object oblate oblige oblong oboe oboist obscene obsess obtain obtrude obtuse
obverse obviate ocarina occlude occur ocean ocelot ocher ochre ocker octal octet
octopus ocular oddball odder oddity oddly oddment oddness odds odes odic odious
odium odorous odour odyssey oecus oeuvre offal offbeat offer offhand office offload
offset often ogive ogle ogling ogre ohed ohing ohmic ohms ohos oiks
oiled oilier oilman oils oily oink okapi okay okra olden oldie oldness
oldster oleo oles olive ology omega omen omicron ominous omit omnibus once
oneness onerous ones ongoing onion online only onrush onset onshore onside onto
onus onward onyx oodles oohed oohs oomph oops ooze oozier oozy opacity
opal opaque oped open opera opes opiate opine opossum oppose oppress opted
optic opts opulent opus oracle oral orange orate orbed orbit orbs orca
orchid orcs ordain ordinal ordure oregano ores orgies oriels orifice origin oriole
orison ormolu ornate orotund orris ortho orzo osier osmium osmosis osprey ossify
ostler ostrich other otiose otter ouch ought ounce ours oust outage outcry
outdo outed outfit outgo outing outlaw output outran outs outta outvote outwit
ouzo oval ovary ovate oven oviduct ovoid ovule ovum owed owes owing
owlet owlish owls owned owning owns oxbow oxen oxide oxtail oxygen oyster
ozone pabulum pace pacify pack pact pacy paddy padlock padre pads paean
paella pagan page paging pagoda paid pail pair paisley palace pale palfrey
paling pall palm palpate paltry pamby pampas panama pancake panda pane pang
panky panned panoply pans pant papa paper papist papoose pappi paprika paps
papyri parboil parch pardon pare parfait pariah park parley parody parquet parry
pars part parvenu paschal pasha pass past patch pate patio patois patrol
pats patty paua paucity paunch pauper pause pave paving pawed pawing pawl
pawn paws paxes payable payback payee paying payload payment payout payroll pays
peace peafowl peahen peak peal peanut pear peas peat pebble pecan peccary
peck pecs pectic pedal peddle peed peeing peek peel peen peep peer
pees peeve peewee pegged pegs peke pekoe pelagic pelf pelican pellet pelmet
pelt pelvic penal pence pendant penguin penman penny pens pent penury peon
people peppy peps peptic perch perfect pergola perhaps perjure perk perm perplex
perry person pert peruke pervade peseta pesky peso pessary petal peter petite
petrel pets petty petunia pewee pewit pews pewter peyote pfennig phaeton phage
phalli phantom pharynx phase phat phenol phew phial phis phiz phlegm phlox
phobia phoebe phone phooey photo phrase phyla phys piano piazza pibroch pica
piccolo pick picnic picot pics picture piddle pidgin piebald piece pied pieing
pier pies piety piffle pigeon piggy piglet pigment pigs pigtail piing pike
piking pilaf pile pilfer pilgrim piling pill pilot pimento pinball pinch pine
ping pinhead pining pink pinned pinon pins pint pinup piny pioneer pious
pipe pipit pipped pips pique piracy pirk pismire pita pitch piteous pitfall
pith pitied piton pits pitted pity pivot pixel pixie pixy pizza place
plaid plan plaque plash plat plaudit play plaza plea pleb plectra pledge
plenty pleura plexus pliant plied plight plinth plod plonk plop plosive plot
plover plow ploy pluck plug plum plunk plural plus pluvial plying plywood
poach pock pocus podded podgy podium pods poem poesy poet pogo pogrom
point poke pokier poky polar pole polio polka poll polo pols poly
pomade pommel pomp poms poncho pond pone pong ponies pons pontiff pony
pooch poodle pooed poof pooh pool poor poos popcorn pope popgun poplar
poppy pops popular porch pore porgy poring pork porous port pose posh
posit posse post posy potash potent potful pothead potion pots potty pouch
pouf poultry pound pour pout powder power powwow poxes praetor praise praline
pram prank prate prawn pray preach precede predate preen pref preheat prelacy
premed prep prequel press pretty prevail prey pride pried prig prim print
prior prithee privy prize probe proceed prod profs progeny project prolix prom
prone proof prop prorate pros proton proud prove prow proxy prude prune
prying psalm pseudo pshaw psis pubic public pubs puce puck puddle pudenda
pudgier puds pueblo puerile puff pugs puke puking pukka pule puling pull
pulp pulse puma pumice pummel pump punch pundit pungent punk punned puns
punt puny pupa pupil puppy pups purdah pure purge purify purl purple
purr purse purvey push pustule putrid puts putt putz puzzle pwned pygmy
pylon pyramid pyrite python pyxes pyxis pzazz quack quad quaff quail quake
qualm quango quash quaver quay qubit queasy quell quench query quest queue
quibble quick quid quiet quiff quill quint quip quire quit quiver quiz
quoin quoll quondam quorum quota rabbi raccoon race rack racy radar radii
radon rads raffia raft raga ragbag ragged raging raglan ragout rags ragtag
ragwort rail raiment rain raise rajah rake raking rally ramble ramekin ramie
ramjet rammed ramp ramrod rams ranch rand ranee rang rank rant rapped
raps rapt rare raring rascal rash rasp raster rata ratchet rate rather
ratio ratline rats ratty raucous raunchy rave ravine rawer rawhide rawly rawness
rayed rayon rays raze razing razor razz reach read reagent real ream
reap rear reason rebate rebel rebid reboot rebus recap recce recede recheck
recipe reckon reclaim recoil recross recur recycle redact redcap redden redeem redhead
redid redly redness redo redraw reds reduce redwood redye reed reef reek
reel reeve reface refer refit reflex refold refract refs regal regent reggae
regime regnant regret regular rehab rehear rehire rehouse rehung reign reiki rein
reissue reject rejig rejoin relent relic reload rely remedy remit remnant remote
rems renal rend renew rennet renown rent reoccur reopen reorder repay repel
repine reply report repress reps reptile repute request reran reread reroute rerun
resat rescue reset reship resin resold respect rest result retail retch retell
rethink retie retold retro retsina return retype reunify reuse revamp revel review
revoke revs revue revved reward reweave rewind reword rewrite rezone rhea rheme
rhenium rhesus rheum rhino rhizome rhodium rhombus rhos rhubarb rhyme rhythm rial
ribald ribbed ribs rice rich ricks ricotta ridden ride ridge riding rids
rife riff rift rigged right rigid rigor rigs rile riling rill rime
rimless rimmed rims rimu rind ring rink rinse ripcord ripe riposte ripped
rips rise rising risk risotto rissole rite ritzy rival rive riving rivulet
riyal roach road roam roan roar roast robbed robe robin robot robs
robust rock rococo rode rods roebuck roes roger rogue roil roister role
roll roly romance romeo romp rondo rood roof rook room roost root
rope roping ropy rosary rose rosin roster rosy rota rote rotor rots
rotted rotund roue rouge round rouse rout roux rove roving rowan rowdy
rowed rowing rows royal rubato rubbed rubdown rubella rubies ruble rubric rubs
ruby ruche ruck ruddy rude rued rueful rues ruff rugby rugged rugs
rule ruling rumba rumen rummy rumor rump rums runaway rune rung runic
runlet runny runs runt runway rupee rupiah rupture rural ruse rush rusks
russet rust ruts rutty ryes saber sable sabot sabra sachem sack sacra
sacs sadden sades sadhu sadly sadness safari safe saffron saga sage saggy
sago sags saguaro sahib said sail saint saith sake salad sale saline
sally salmon salon salsa salt salute salve samba same samovar sampan samurai
sanctum sand sane sang sanity sank sans sapient sapless sappy saps sapwood
saran sarcasm sardine sarge sari sarky sarong sash sass satchel sate satin
satrap satyr sauce sauna saurian sausage saute savage save saving savoys savvied
sawdust sawed sawfly sawing sawmill sawn saws sawyer saxes sayer saying says
scad scag scam scan scapula scat scene schema schism schlep schmo school
schuss schwa sciatic science scion scissor scoff scold scone scoop scope score
scotch scowl scrag scree scrim scrub scuba scud scuff scull scum scupper
scurf scuttle scythe seabed seafood seagull seal seam seaport sear seas seat
seaway sebum secant secede seclude second secret secs sect secure sedan sedge
seduce seed seeing seek seem seen seep seer sees seethe segment segue
seine seismic seldom select self sell seltzer selves semi senate send senile
senna senor sense sent sepal sepia sepoy sequel serape sere serf serge
serif sermon serous serpent serrate serum serve sesame session seta setback sets
setts setup sewage sewed sewing sewn sews sexier sexless sexpot sextet shabby
shade shaft shah shake shale sham shank shape shard shave shawl shay
shchi sheaf shed sheen sheik shekel sherry shes shew shiatsu shied shift
shill shim shin ship shire shiver shoal shock shod shoe shogun shone
shop shore shout shove show shrank shred shriek shrub shtick shuck shudder
shuffle shun shush shut shyer shying shyly shyness sibling sibyl sics side
siding sidle sienna sierra siesta sieve sift sigh sigil sigma sign silage
silent silica silk sill silo silt silver simian simmer simony simper sims
since sine sinful sing sink sinless sinned sins sinus siphon sipped sips
sire siring sirloin sirocco sirs sisal sises sissy sister sitar sitcom site
sits sitter situate sive sixes sixfold sixth size sizing sizzle skate skeet
skein sketch skew skid skied skiff skiing skill skim skin skip skirt
skis skit skivvy skoal skol skua skulk skunk skydive skyey skying skyjack
skylark skyward slab slack slag slake slalom slam slang slap slat slaw
sleaze sled sleek sleigh slender slept sleuth slew slice slid slier slight
slim sling slip slit sliver slob sloe slog sloop slop slosh slot
slouch sloven slow sludge slue slug sluice slum slung slur slush slyer
slyly slyness smack small smart smash smear smell smidgen smile smirk smite
smock smog smoke smolt smooch smote smudge smug smurf smut snack snafu
snag snail snake snap snare snatch snazzy sneak sneer snick snide sniff
snitch snivel snob snog snood snore snot snout snow snub snuff snug
soak soap soar sober sobs soccer social sock soda sodded sodium sodomy
sods soever sofa soft soggy soil soiree sojourn solar sold sole solid
solo sols solute solve somatic some sonar song sonic sonny sons sook
soon soot sophism soppy soprano sops sorbet sorcery sordid sore sorghum sort
sots sottish sough souk soul sound soup sour sous south soviet sowed
sowing sown sows soya space spade spake spam span spar spas spat
spavin spawn spay speak speck sped speed spell spend spew sphere sphinx
spice spider spied spiffy spigot spike spill spin spire spit spiv splat
spleen split splodge splurge spoil spoke sponge spoof spore spot spout sprat
spree sprig sprout spruce spry spud spume spur sputa spying squab squeak
squib stack stadium staff stag staid stake stale stamp stand staple stash
state staunch stave stay stdio stead steed stein stellar stem step stern
stet stew stick sties stiff stigma stile stimuli sting stipend stir stitch
stoat stock stodge stoic stoke stole stomp stone stood stop store stoup
stove stow strew stria strum stub stuck stud stuff stump stun sturdy
stutter style stymie styptic suasion suave subbed subdue subhead subject sublet submit
suborn subs subtle suburb subvert subway subzero succeed such suck sucrose suction
sudden suds sued suer sues suet sugar suggest suing suit sulfa sulk
sully sultan sumac summed sumo sump sums sunbath sundae sunfish sung sunk
sunlit sunny sunrise suns suntan sunup super supine supped supra sups surd
sure surf surly surmise surname surpass surreal surtax survey sushi suspect suss
sustain sutler svelte swab swaddle swag swain swallow swam swan swap sward
swash swat sway swear swede sweep swept swerve swift swig swill swim
swine swipe swirl swish switch swivel swizzle swollen swoon sword swot swum
swung sylph sylvan symbol symptom synapse sync synergy synod syntax syrup sysop
system tabby tabla taboo tabs tabular tacit tack taco tact tadpole tads
taffeta tagged tagma tags taiga tail taint take taking talc tale tali
talk tall talon talus tamale tame taming tamp tams tanager tanbark tandem
tang tank tanned tans tantrum tapas tape tapir tapped taproom taps tardy
tare target tariff tarmac tarn taro tarpon tarry tars tart task tassel
taste tater tats tatty taught taunt taupe taus taut tavern tawdry tawny
taws taxable taxed taxi taxon teabag teach teak teal team teapot tear
teas teat techs teddy tedium teds teed teeing teem teen tees teeth
tektite telco telex tell temp tenant tench tend tenet tenfold tennis tenon
tenpin tens tent tenure tepee tepid tequila terbium term tern terse tetchy
tether tetra text thalami than that thaw theca thee theft their them
then theory there these theta thew they thick thief thigh thimble thin
third this thither thole thong thorn those thou thrall thrice throb thrum
thud thulium thumb thunder thus thwack thyme thyroid thyself tiara tibia tick
tics tidal tiddly tide tidied tidy tieback tied tier ties tiff tiger
tight tigress tiki tilde tile tiling till tilt timber time timid timpani
tinder tine tinfoil ting tinier tinker tinny tins tint tinware tiny tipped
tips tiptoe tirade tire tiring tissue titan titch tithe title titmice titre
titular tizz toad toast tobacco toccata tock tocsin today toddy toecap toed
toehold toeing toenail toes toffee tofu toga togged togs toil toity token
told tole toll toluene tomato tomcat tome toms tomtit tonal tone tong
tonic tonne tons tony took tool toot topaz topcoat topee topic topknot
topless topmast topped tops toque torch tore torment torn torpid torque torrid
torso torus tosh toss total tote toting tots totted touch tough toupee
tour tousle tout toward towed towing town tows toyed toying toys trace
trade traffic trail tram trance trap trash travel trawl tray tread treble
tree trefoil trek trellis trend tress trews trey triad tribe trice trident
tried trifle trig trike trill trim trinity trio trip trireme trisect trite
triumph trivet trochee trod troika troll tromp tron troop trope trot trout
trove trowel troy truant truce trudge true truffle trug truing truly trump
trunk truss truth trying tryst tsar tsetse tsunami ttys tuba tubby tube
tubing tubs tubule tuck tuft tugboat tugged tugs tuition tulip tulle tumble
tumid tummy tums tumult tuna tundra tune tunic tunny tuns tuple tuque
turbo tureen turf turgid turkey turmoil turn turps turret turtle turvy tush
tusk tussle tutor tuts tutti tutu tuxes twaddle twain twang twas tweak
twee twelve twenty twerp twice twiddle twig twill twin twirl twist twit
twixt twofold twos tycoon tying tyke tympani type typify typo tyrant tyre
tyro tzar udder ukase ukulele ulna ulsters ultimo ultra ululate umbel umbo
umbra umiak umlaut umped umpire umps umpteen unable unaided unalike unarmed unasked
unaware unbar unbend unbind unblock unbolt uncanny unchain uncial uncle uncoil uncross
unction uncut undated undid undo undress undue undying unease unequal uneven unfair
unfed unfit unfold unfrock unfurl unglued ungodly unguent unhand unheard unhinge unholy
unhurt unicorn unify union unique unisex unit unjam unjust unkempt unkind unknown
unlace unless unlit unload unlucky unmade unmet unmixed unmoved unnamed unnerve unpack
unpeg unpin unplug unquote unravel unread unripe unroll unruly unsafe unscrew unset
unshod unsnap unsold unspent unstrap unsung untamed untie unto untrue untwist untying
unused unveil unwary unwed unwind unworn unwrap unyoke unzip upbeat upbraid update
upend upfront upgrade upheld uphill uphold upkeep upland uplift upload upon upped
upping upraise upright uproar upscale upset upshot upside upstage upsurge upswing uptake
uptight uptown upturn upward upwind uracil uranium urban urchin urea ureter urge
urging uric urine urns urology ursine usable usage used useful useless user
uses usher using usual usurp utan utensil uteri utility utmost utopia utter
uucp uvula vacant vaccine vacs vacuum vagary vagrant vague vain valance vale
valid valley valor value valve vamp vane vanish vans vantage vape vapid
vapor varied varlet varnish varsity vary vase vassal vast vats vatted vault
vaunt veal vector veep veer vegan veges veggie vehicle veil vein velar
veld vellum velour velum velvet venal vend veneer venial vent venue veranda
verb verdant verge verify vermin vernal verruca versa vertex verve very vesicle
vesper vessel vest vetch veteran veto vets vetted vexed vexing viable viaduct
vial viand vibe vibrant vicar vice vicious video vied vies view vigil
vigor vile vilify villa vine vino vintage vinyl viper viral vireo virgin
virile virtue visa viscid vise visit visor vista visual vita vitiate vitrify
viva vivid vivo vixen vizier vocal vodka vogue voice void voile volcano
vole volley volt volume voodoo vortex votary vote voting vouch vowed vowing
vows voyage voyeur vroom vulgar vulpine vulture vying wacky waddle wade wadge
wading wads wafer waffle waft wage wagged waging wagon wags wagtail waif
wail wain waist wait waive waka wake waking waldo wale waling walk
wall walnut walrus waltz wampum wand wane wangle waning wanly wannabe want
wapiti warble ward ware warier warm warn wart wary wash wasp wassail
wast watch water watt wave wavier wavy waxed waxier waxwing waxy waylay
ways wayward wazoo weak weal wean wear weasel weather weave webbed webs
wedded wedge wedlock weds weed week weeny weer wees weevil weft weigh
weir weka welcome weld welfare well welsh wench wend wens went wept
were west weta wetly wetness wets wetter whack whale wham wharf what
wheat wheel whelk when where whet whew whey which whiff while whim
whine whir whisk whit whiz whoa whoever whole whom whoop whop whose
whup whys wick wide widget width wield wife wigged wight wigs wigwag
wiki wild wile wilier will wilt wily wimp wince wind wine wing
wining wink winner wino wins winter winy wipe wiping wire wirier wiry
wisdom wise wish wisp wistful witch with witless witness wits witty wives
wizard wizened wkly woad wobble wodge woeful woes wogs woke woks wold
wolf wolves woman womb women wonder wonky wont wood wooed woof wooing
wool woos woozy wops word wore work world worm worn worry worse
worth would wove wowed wowing wows wrack wraith wrangle wrap wrasse wrath
wreak wren wrest wretch wriggle wring wrist writ wrong wrote wrought wrung
wryer wryly wryness wurst wuss xenon xerox xref xterm xylem xylol yabby
yacht yack yahoo yakka yaks yammer yams yang yank yapped yaps yard
yarn yarrow yawed yawing yawl yawn yawp yaws yeah year yeas yegg
yell yelp yens yeoman yeps yeses yest yeti yews yids yield yikes
yipe yippee yips yobbo yobs yodel yoga yogi yoke yoking yolk yonder
yonks yore york young your yous youth yowl yttrium yuan yucca yucky
yukky yuks yule yummy yuppie yups yurt zanier zany zapped zaps zeal
zebra zebu zeds zein zenith zens zephyr zero zest zeta zigzag zilch
zillion zinc zine zing zinnia zippy zips zipx zircon zither zits zloty
zodiac zombie zonal zone zoning zonked zoology zoom zoos zorch zygote zymurgy
`;

/** The list, index order. The index of a word is part of the code format: never re-sort. */
export const WORDS = Object.freeze(WORDLIST.trim().split(/\s+/));

/** SHA-256 of WORDS.join('\n') + '\n', hex. Recomputed by tests/crypto.test.mjs. */
export const WORDLIST_SHA256 = 'bcc957797cf6e7ce41a54ca0e0873946330bdc8390688eabc801906f7f120176';

export const WORD_COUNT = WORDS.length; // 7776 = 6^5, one five-dice throw per word
export const CODE_WORDS = 8; // 8 * log2(7776) = 103.40 bits
export const WORD_BITS = 13; // 2^13 = 8192, the smallest power of two >= 7776
export const PREFIX_LEN = 4; // the guaranteed-unique prefix
export const CODE_PREFIX = 'WARP';

// A wrong list is not a degraded gate code, it is a different one, and it would fail as
// a mismatch on the far device rather than as an error here. Check it at load: a module
// that cannot do its job must refuse to load rather than mint codes nobody can read.
if (WORD_COUNT !== 7776) {
  throw new Error(`gate-code wordlist must hold exactly 7776 words, found ${WORD_COUNT}`);
}

const INDEX = new Map();
const BY_PREFIX = new Map();
for (let i = 0; i < WORDS.length; i += 1) {
  INDEX.set(WORDS[i], i);
  BY_PREFIX.set(WORDS[i].slice(0, PREFIX_LEN), WORDS[i]);
}
if (INDEX.size !== WORD_COUNT || BY_PREFIX.size !== WORD_COUNT) {
  throw new Error(`gate-code wordlist is not unique: ${INDEX.size} distinct words, ${BY_PREFIX.size} distinct ${PREFIX_LEN}-character prefixes`);
}

/**
 * Every rejection a human can cause, with a reason code the UI can branch on and a
 * message it can show unchanged. `reason` is the contract; the wording is not.
 *
 *   empty    nothing was entered
 *   legacy   the pre-2026-08-09 base32 code, which no longer means anything
 *   count    the right kind of thing, the wrong number of words
 *   typo     a word that is not on the list but whose first four characters are
 *   unknown  a word that is not on the list and is not close to one
 *   charset  a character that cannot appear in a code at all
 */
export class GateCodeError extends Error {
  constructor(reason, message, detail = {}) {
    super(message);
    this.name = 'GateCodeError';
    this.reason = reason;
    Object.assign(this, detail);
  }
}

// ---------------------------------------------------------------- sampling

const MASK = (1 << WORD_BITS) - 1; // 0x1fff

const cryptoFill = (buf) => globalThis.crypto.getRandomValues(buf);

/**
 * `count` uniformly distributed word indices, by rejection sampling.
 *
 * Thirteen bits give 8192 values for 7776 words, so 416 values have no word. They are
 * DISCARDED and redrawn. The obvious alternative, `value % WORD_COUNT`, would fold those
 * 416 values back onto words 0 to 415 and make each of them exactly twice as likely as
 * every other word. That costs about 0.07 bits per word, which is small, but the real
 * damage is not the entropy: it hands an attacker a search order, and a code is worth
 * attacking precisely because it is only 103 bits before stretching. Rejection sampling
 * costs one extra pair of bytes 5.1 percent of the time and has no bias to argue about.
 *
 * `fill` is injectable so the test can walk the whole 13-bit domain and prove that every
 * word comes out exactly once and that exactly 416 draws are rejected. It defaults to
 * crypto.getRandomValues and nothing in the app ever passes it.
 */
export function randomWordIndices(count = CODE_WORDS, fill = cryptoFill) {
  const out = new Uint16Array(count);
  const draw = new Uint8Array(2);
  for (let i = 0; i < count; i += 1) {
    let value;
    do {
      fill(draw);
      value = ((draw[0] << 8) | draw[1]) & MASK;
    } while (value >= WORD_COUNT);
    out[i] = value;
  }
  return out;
}

// ---------------------------------------------------------------- encoding

function assertIndices(indices) {
  const list = indices instanceof Uint16Array ? indices : null;
  if (list === null || list.length !== CODE_WORDS) {
    throw new TypeError(`a gate code is ${CODE_WORDS} word indices in a Uint16Array, got ${indices instanceof Uint16Array ? `${indices.length} of them` : typeof indices}`);
  }
  for (const i of list) {
    if (i >= WORD_COUNT) throw new RangeError(`word index ${i} is outside the ${WORD_COUNT}-word list`);
  }
  return list;
}

/** The displayed form: capitals, hyphen separated, WARP prefix. */
export function encodeWordIndices(indices) {
  const words = [...assertIndices(indices)].map((i) => WORDS[i].toUpperCase());
  return `${CODE_PREFIX}-${words.join('-')}`;
}

/**
 * The hashed form: lowercase, single spaces, no prefix. crypto.js feeds exactly this
 * string to PBKDF2, so it is frozen forever even if the display changes.
 */
export function canonicalPhrase(indices) {
  return [...assertIndices(indices)].map((i) => WORDS[i]).join(' ');
}

/** A fresh code, ready to display. */
export function generateGateCode() {
  return encodeWordIndices(randomWordIndices());
}

// ---------------------------------------------------------------- decoding

// Chat clients, note apps and PDF viewers rewrite a plain hyphen into a typographic dash
// and a plain space into a non-breaking one. Those are SEPARATORS, not symbols: they are
// folded away before anything is looked up, so accepting them adds no new spelling of any
// code, it only stops a paste from a real client failing for a reason nobody can see.
const FANCY_SEPARATORS = /[\u00a0\u2010-\u2015\u2043\u2212\u2e3a\u2e3b]/g;
const SEPARATORS = /[-\s]+/;

// The pre-2026-08-09 code was 26 Crockford base32 symbols carrying a 128-bit secret. The
// person holding one needs to be told the format changed, not that their code is
// malformed. Old gates are all long dead, so there is nothing to migrate: the message is
// the whole feature.
//
// The test is "alphanumeric with at least one DIGIT in it", not "26 characters long".
// Length alone was wrong and the mutation suite caught it: six four-and-five letter words
// also strip to 26 characters, so a truncated word code was being reported as an old
// code. A digit is proof, because every word on the list is letters only. The residual is
// the other way round and is tiny: an old code drawn without a single digit, about 1 in
// 17000, falls through and gets the unknown-word message instead.
const LEGACY_BODY = /^(?=[0-9a-z]*[0-9])[0-9a-z]+$/;

/**
 * Text -> `{ indices, code, phrase }`, or a GateCodeError naming what is wrong.
 *
 * Accepts the bare words, the words with the WARP prefix, or a whole link. A link is
 * split on the FIRST '#' and only the fragment is considered, because the secret only
 * ever travels in the fragment and because scanning the whole string for "WARP" breaks
 * every origin with "warp" in it: warp.example.com, example.com/warp/, warpgate.io were
 * all rejected by the version of this that did that.
 */
export function decodeGateCode(text) {
  const raw = String(text ?? '').replace(FANCY_SEPARATORS, '-').trim();
  if (!raw) throw new GateCodeError('empty', `A gate code is ${CODE_WORDS} words. Nothing was entered.`);

  const hashAt = raw.indexOf('#');
  const candidate = (hashAt >= 0 ? raw.slice(hashAt + 1) : raw).trim();

  // ASCII only, and checked before any case folding. Unicode default case conversion
  // folds characters from outside the alphabet onto it (U+0131 dotless i uppercases to
  // 'I', U+017F long s to 'S'), which would create extra spellings of a word. Reject
  // rather than let toLowerCase decide, exactly as base32Decode does in crypto.js.
  for (const ch of candidate) {
    if (ch.codePointAt(0) > 0x7f) {
      throw new GateCodeError('charset', `A gate code is ${CODE_WORDS} plain words. "${ch}" is not a character a code can contain.`, { char: ch });
    }
  }

  let tokens = candidate.split(SEPARATORS).filter((t) => t.length > 0).map((t) => t.toLowerCase());
  // "warp" is denied from the wordlist precisely so that a leading WARP token is always
  // the display prefix and never the first word.
  if (tokens.length > 0 && tokens[0] === CODE_PREFIX.toLowerCase()) tokens = tokens.slice(1);

  const stripped = tokens.join('');
  if (LEGACY_BODY.test(stripped)) {
    throw new GateCodeError('legacy', `That is an old-style Warp Gate code. Gate codes are now ${CODE_WORDS} words, and any gate made with an old code has already expired: ask for a new link.`);
  }

  if (tokens.length !== CODE_WORDS) {
    throw new GateCodeError('count', `A gate code is ${CODE_WORDS} words. This one has ${tokens.length}.`, { count: tokens.length });
  }

  const indices = new Uint16Array(CODE_WORDS);
  for (let i = 0; i < CODE_WORDS; i += 1) {
    const word = tokens[i];
    const found = INDEX.get(word);
    if (found !== undefined) { indices[i] = found; continue; }
    // The list guarantees a unique four-character prefix, so a word mistyped after its
    // fourth character identifies exactly one candidate and the message can name it. A
    // near miss is NOT accepted silently: a code is transcribed, not composed, and
    // quietly repairing it multiplies the accepted spellings of one secret, which is the
    // thing base32Decode was hardened against. Say what is wrong and let the human fix it.
    const near = word.length >= PREFIX_LEN ? BY_PREFIX.get(word.slice(0, PREFIX_LEN)) : undefined;
    if (near !== undefined) {
      throw new GateCodeError('typo', `Word ${i + 1} of ${CODE_WORDS} is "${word}", which is not on the word list. Did you mean "${near.toUpperCase()}"?`, { position: i + 1, word, suggestion: near });
    }
    throw new GateCodeError('unknown', `Word ${i + 1} of ${CODE_WORDS} is "${word}", which is not a Warp Gate word.`, { position: i + 1, word });
  }

  return { indices, code: encodeWordIndices(indices), phrase: canonicalPhrase(indices) };
}

/**
 * decodeGateCode without the throw, for the callers that only want to know whether a
 * string is a code at all. Returns null on any human-caused rejection and rethrows
 * anything else, so a genuine bug in here never disguises itself as "not a code".
 */
export function tryDecodeGateCode(text) {
  try {
    return decodeGateCode(text);
  } catch (err) {
    if (err instanceof GateCodeError) return null;
    throw err;
  }
}
