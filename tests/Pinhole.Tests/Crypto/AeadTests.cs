using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Pinhole.Crypto;
using Xunit;
using Aead = Pinhole.Crypto.Aead;
using BcChaChaPoly = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace Pinhole.Tests.Crypto;

public sealed class AeadTests
{
    private static readonly (int Id, int KeyLen, string Key, string Iv, string Aad, string Msg, string Ct, string Tag, bool ExpectOpen)[] AesGcmRows =
    [

            (1, 16, "5b9604fe14eadba931b0ccf34843dab9", "028318abc1824029138141a2", "", "001d0c231287c1182784554ca3a21908", "26073cc1d851beff176384dc9896d5ff", "0a3ea7a5487cb5f7d70fb6c58d038554", true),
            (2, 16, "5b9604fe14eadba931b0ccf34843dab9", "921d2507fa8007b7bd067d34", "00112233445566778899aabbccddeeff", "001d0c231287c1182784554ca3a21908", "49d8b9783e911913d87094d1f63cc765", "1e348ba07cca2cf04c618cb4d43a5b92", true),
            (3, 16, "aa023d0478dcb2b2312498293d9a9129", "0432bc49ac34412081288127", "aac39231129872a2", "2035af313d1346ab00154fea78322105", "eea945f3d0f98cc0fbab472a0cf24e87", "4bb9b4812519dadf9e1232016d068133", true),
            (4, 16, "bedcfb5a011ebc84600fcb296c15af0d", "438a547a94ea88dce46c6c85", "", "", "", "960247ba5cde02e41a313c4c0136edc3", true),
            (5, 16, "384ea416ac3c2f51a76e7d8226346d4e", "b30c084727ad1c592ac21d12", "", "35", "54", "7c1e4ae88bb27e5638343cb9fd3f6337", true),
            (6, 16, "cae31cd9f55526eb038241fc44cac1e5", "b5e006ded553110e6dc56529", "", "d10989f2c52e94ad", "a036ead03193903f", "3b626940e0e9f0cbea8e18c437fd6011", true),
            (7, 16, "dd6197cd63c963919cf0c273ef6b28bf", "ecb0c42f7000ef0e6f95f24d", "", "4dcc1485365866e25ac3f2ca6aba97", "8a9992388e735f80ee18f4a63c10ad", "1486a91cccf92c9a5b00f7b0e034891c", true),
            (8, 16, "ffdf4228361ea1f8165852136b3480f7", "0e1666f2dc652f7708fb8f0d", "", "25b12e28ac0ef6ead0226a3b2288c800", "f7bd379d130477176b8bb3cb23dbbbaa", "1ee6513ce30c7873f59dd4350a588f42", true),
            (9, 16, "c15ed227dd2e237ecd087eaaaad19ea4", "965ff6643116ac1443a2dec7", "", "fee62fde973fe025ad6b322dcdf3c63fc7", "0de51fe4f7f2d1f0f917569f5c6d1b009c", "6cd8521422c0177e83ef1b7a845d97db", true),
            (10, 16, "a8ee11b26d7ceb7f17eaa1e4b83a2cf6", "fbbc04fd6e025b7193eb57f6", "", "c08f085e6a9e0ef3636280c11ecfadf0c1e72919ffc17eaf", "7cd9f4e4f365704fff3b9900aa93ba54b672bac554275650", "f4eb193241226db017b32ec38ca47217", true),
            (11, 16, "28ff3def08179311e2734c6d1c4e2871", "32bcb9b569e3b852d37c766a", "c3", "dfc61a20df8505b53e3cd59f25770d5018add3d6", "f58d453212c2c8a436e9283672f579f119122978", "5901131d0760c8715901d881fdfd3bc0", true),
            (12, 16, "e63a43216c08867210e248859eb5e99c", "9c3a4263d983456658aad4b1", "834afdc5c737186b", "b14da56b0462dc05b871fc815273ff4810f92f4b", "bf864616c2347509ca9b10446379b9bdbb3b8f64", "a97d25b490390b53c5db91f6ee2a15b8", true),
            (13, 16, "38449890234eb8afab0bbf82e2385454", "33e90658416e7c1a7c005f11", "4020855c66ac4595058395f367201c4c", "f762776bf83163b323ca63a6b3adeac1e1357262", "a6f2ef3c7ef74a126dd2d5f6673964e27d5b34b6", "b8bbdc4f5014bc752c8b4e9b87f650a3", true),
            (14, 16, "6a68671dfe323d419894381f85eb63fd", "9f0d85b605711f34cd2a35ba", "76eb5f147250fa3c12bff0a6e3934a0b16860cf11646773b", "0fc67899c3f1bbe196d90f1eca3797389230aa37", "bd64802cfebaeb487d3a8f76ce943a37b3472dd5", "fce9a5b530c7d7af718be1ec0ae9ed4d", true),
            (15, 16, "bb571c160132b0c8d5d190d0bc356ddc", "2596c440cf0232950ec66bc4", "", "053be1b6190a717fc74c879e6fd62dc44628495507e50d662271dee795a4ad26e0c4f86cb6b20ac6bd9d682d2d8a05c9dad875a6911b49ea0af4f17c97a5f2", "b1cfad142a462f3656e0921627fd41d4f1fa8e2f8bd94bb51fdcf06f606296f7d2885337bed7a4ca6ddb4a9fc7fdb2476b5f7fa5220e1d6752a5e7c31c916c", "a231b617352ffdb63d32d69d99e7d629", true),
            (16, 16, "e12260fcd355a51a0d01bb1f6fa538c2", "5dfc37366f5688275147d3f9", "", "d902deeab175c008329a33bfaccd5c0eb3a6a152a1510e7db04fa0aff7ce4288530db6a80fa7fea582aa7d46d7d56e708d2bb0c5edd3d26648d336c3620ea55e", "d33bf6722fc29384fad75f990248b9528e0959aa67ec66869dc3996c67a2d559e7d77ce5955f8cad2a4df5fdc3acccafa7bc0def53d848111256903e5add0420", "8bc833de510863b4b432c3cbf45aa7cc", true),
            (17, 16, "97ec85a69a05131cd4ff643972f6d8f9", "9189e0eedcc413a0ba1e63d2", "", "10acefa6f3959faecb5cfdaee8aaf09d4381b2b147e0b13450c26ee07f29edaa9a1f1af4e2d111dea7ff681a19fc3a4fd66df6a17985b06543a3b6c0e4e51a54b7", "eefdf89997244e065ff19ac2374dc92ee76899ddcbe7c834dcc657242fc0f6dd38272373ba9b549316a36f1522e1cab246157875898c966eec563d57eca5c7d32d", "23aaa2c6b680fcaaeb2c7a55726d4bc0", true),
            (18, 16, "65d38f0b268f180d6ba548d509111dde", "e14dfc27394ac846c2373ea7", "", "1fa76d7995dc996a5f5dabaa4be401be14f4d4706a213a4dd725df386ec147a6be074947c733094f47a7222552376740aa8348a0ae1c7f2d972a0ad664f8b8ec81dfc9af078b61daea5dde874fd73775b4cd65acf069ada0b2b9bfbb4a9817ba41d4dcaff7653df5c8cd9ce7f59eec92ae9e61314e03ef48839810ea825520", "40dc9b139e888f1811391134b15e914826414a99db512a0632dc4c56d70f7b7991e9945a2025890e951699cf6b2ccee093c9a6a752b98ff696240126759f480299c1dd82aa2c4f462a4a8ad1ad0c7a755f07908c9c0d336d57dbdebc940bbae28ba0336dccaf6bfdc93623686f9487ef0884d100b6b98949afbd4217dc4640", "4218d6ac98c0444bc64ecbe1d763136a", true),
            (19, 16, "3c55f88e9faa0d68ab50d02b47161276", "d767c48d2037b4bd2c231bbd", "", "5d6add48e7a5704e54f9c2829a9b4283dce0d3a65b133eba3793c4fbfa1d8e3a2539d0d4f3de381598ce5b2360173fbd149476c31692c5d6e872fce40219378949c2e70b5f1b9f0a1d5f38352ad814b2a035bb3f3f26425d831a2f7a5e65c5dfcd91a315c2b24f53a662605ea40857dd980e9be5cdad000c569f2d204d4bd3b0", "17d72d90bd23e076d8364a87ecb9ac58acc5de4629bfd590409b8bf1fcd3a2f602731b4614cec15e773ea65a65e7210994256bf5450a25acb527269c065f2e2f2279d1fe8b3eda98dcf87b348f1528377bbdd258355d46e035330483d8097e80c7de9bbb606ddf723f2909217ffdd18e8bdbd7b08062f1dcba960e5c0d290f5f", "090b8c2ec98e4116186d0e5fbefeb9c2", true),
            (20, 16, "62b3881832d428b6f900cacfa0fc5cd8", "f4cb98cc99e7bc424a98384e", "", "0b91dd36a6fa967a257b267d12cbc20b56ed615b205d044a04b4ae8aaa365bd29a3b8f47a0828ef63324d1ff924c68090abaaad78df602edee0621b823f94c35ada7b62d81f21dd9945d1abb4ef882cfab12c2e4cec705df3d669183fe681753503a99a871637953537ef479b1f62de7819dbb5c950de7722090942d38129aefa7", "00574615883e222657bdf34e9327888f5d532d086581834c62adf54c7fee46927ca27cba193d86c6140b3610a2cd16ba295814b5b7d6a1c8d3f039e0e8f8d7942b0616a9b9f0012884311b0c370f9dd6b9a3d8b6ff36177683c0dd858850dd29993b3eec89a2ab8068038e2c86a2e71b5cacdb38ad69ac0580e29a6f7813c17258", "88b99f768364ff9e95a94ccbbc1b166e", true),
            (21, 16, "8aeaa2591a452e626b9a6468b623bdfc", "b90f446f68aea588d843d01a", "", "f0721c3b68d905092cada6d568df3a2da39573c7bb0e9a4ed159a2634237f9e788488c06fe8a7e1e01d1a1c985543ecf90f3d32e57d33c3df6c165b7edc6fbcf8bf2d043d1b7c0060309a29565a004ea3214d4e4f7dedeac2d74576c019b5fa000d025917af6f86310942102a34d92781972d4f1f57bbdd6f9b08cc979a358aacf6cb62334bfc916c249f18bcee644a8907ef576b41437098bdf0069767fb5ed1c0f1385e5895e4a5d70f5941a93014333436a7af465ec1038fdfa006410a0871225d64848e6c59ac23f176df663ee2171c9eaec0477f9ebd280880d9f2967a2e791cc998f6b23518ca97bbc6405d6ced3373ebf3d208c2a909274460a614a", "7bb36313569ff8b5c58e41b17a78fa5d780073bee20b55f004532288e7f0a9475076364d8922d389ecd189f597a8a677cb2484513ed7afe2d0691717cd0ac0e27bf7e2257dd7e4ffc0bbf59e92d258e1116fac9bfc84a2df728bdd7ab221754dd341f7229e030dce06474d00f99a5e457943bd9e8f345bcbb5407690d072dfb0113b64bc0e658eeb7226409a5898dd27d995a0be021f351091f9b907ae3a9625f240dee2bf4bb15eb4f30f4abf1ff25ca5536def969d2588188fecacfc7dc75f5c676ca7851f9e805f498372c6b98f5c7d12403723619f80ce5badfe5844643d5631d4998ee0426a2b29159cae2590dc81646c78be5c9e8ffe056aa0d3552e", "fc62295c70d140dbc354fdbc8003eb41", true),
            (22, 16, "e88d95eabe88fcf158fae858af951221", "a65834a9d231b34709383e9a", "", "2decaccc8b424fa4963890ece15b3fc281b6215780ff6baee57edcd25afe260ff80ed4f25cc04d2802a1e90a2e6e96d1ee73a4a53dcf60025d484054d146f275ab34c33b102001a07d804cc94a40fd78c16780d1b648487fac035386e5d25c2b9edbf7a52d102d1943958c009eb6d88e00a3227c4c788e445003fabb4dbefccd3fe1716d916446fee2111615d560ecc59d7bd288268ab321e7002545887183fe023fdec2a6d3b73b94d1548cee19638d31d2c5a32b15d2aae3f42950a787115e200b00022d4929105da0b4d10ccb0b3886b3169b32ac5df7a637c23362e2d4ed9c137f35bbd578c2cda0377e0f1e64f7d31e9ef4d7603ea1363523758385c761", "9b3833c356f83d19f59ac4770c9586aad457810f9dc55112cc6b87e94d8dc71184b227a14500c0a8619d544435db4c001467ef2acba95007299d717fadc0c0717c4c8e748d03ffe2cf2fd06f0009b0e6590f956c212a2c926d5679bdbb79d87636ae9faefa5c8330c570e84b94626f87d6a53b121574f74c9e3211d9451811e9940db5e74d128364328fb8f40f850a25c3e7ba4fdeb0ef6a639060a11d1c32ae0531d2518f905952c9814236b00b9393fd31f8c0522f8e3072b864a3a5cebe1ceb15585c9042f3f5b95390c62d8c1b513550defd21b481fcfbd9fdd6c262ff6ed4e0a6051be309788a763e567107f039e988757f96ad95436792a3bd26f38590", "4f4c265edd3158c641ce9555b58650db", true),
            (41, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d9847dbc326a06e988c77ad3863e6083", false),
            (42, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "da847dbc326a06e988c77ad3863e6083", false),
            (43, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "58847dbc326a06e988c77ad3863e6083", false),
            (44, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d8857dbc326a06e988c77ad3863e6083", false),
            (45, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d8847d3c326a06e988c77ad3863e6083", false),
            (46, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d8847dbc336a06e988c77ad3863e6083", false),
            (47, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d8847dbc306a06e988c77ad3863e6083", false),
            (48, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d8847dbc326a066988c77ad3863e6083", false),
            (49, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d8847dbc326a06e989c77ad3863e6083", false),
            (50, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d8847dbc326a06e908c77ad3863e6083", false),
            (51, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d8847dbc326a06e988e77ad3863e6083", false),
            (52, 16, "000102030405060708090a0b0c0d0e0f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "eb156d081ed6b6b55f4612f021d87b39", "d8847dbc326a06e988c77bd3863e6083", false),
    ];

    private static readonly (int Id, int KeyLen, string Key, string Iv, string Aad, string Msg, string Ct, string Tag, bool ExpectOpen)[] ChaChaRows =
    [

            (1, 32, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "070000004041424344454647", "50515253c0c1c2c3c4c5c6c7", "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e", "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116", "1ae10b594f09e26a7e902ecbd0600691", true),
            (2, 32, "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0", "4da5bf8dfd5852c1ea12379d", "", "", "", "76acb342cf3166a5b63c0c0ea1383c8d", true),
            (3, 32, "7a4cd759172e02eb204db2c3f5c746227df584fc1345196391dbb9577a250742", "a92ef0ac991dd516a3c6f689", "bd506764f2d2c410", "", "", "906fa6284b52f87b7359cbaa7563c709", true),
            (4, 32, "cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273", "99e23ec48985bccdeeab60f1", "", "2a", "3a", "cac27dec0968801e9f6eded69d807522", true),
            (5, 32, "46f0254965f769d52bdb4a70b443199f8ef207520d1220c55e4b70f0fda620ee", "ab0dca716ee051d2782f4403", "91ca6c592cbcca53", "51", "c4", "168310ca45b1f7c66cad4e99e43f72b9", true),
            (6, 32, "2f7f7e4f592bb389194989743507bf3ee9cbde1786b6695fe6c025fd9ba4c100", "461af122e9f2e0347e03f2db", "", "5c60", "4d13", "91e8b61efb39c122195453077b22e5e2", true),
            (7, 32, "c8833dce5ea9f248aa2030eacfe72bffe69a620caf793344e5718fe0d7ab1a58", "61546ba5f1720590b6040ac6", "88364fc8060518bf", "ddf2", "b60d", "ead0fd4697ec2e5558237719d02437a2", true),
            (8, 32, "bd8ed7fb0d607522f04d0b12d42c92570bccc5ba2486953d70ba2e8193f6225a", "d2ab0abb50a8e9fba25429e1", "", "201221", "3cf470", "a27a69c9d7ee84586f11388c6884e63a", true),
            (9, 32, "1c8b59b17a5ceced31bde97d4cefd9aaaa63362e096e863ec1c89580bca79b7a", "94f32a6dff588f2b5a2ead45", "6c8cf2ab3820b695", "453f95", "610925", "a8a7883eb7e40bc40e2e5922ae95ddc3", true),
            (10, 32, "e4912cb75a1174345f1a457366f18885fe8460b06478e04be2f7fb4ec9c113e5", "7aa5ad8bf5254762171ec869", "", "9e4c1d03", "fe6849aa", "99ad07871b25c27defc31a541bd5c418", true),
            (11, 32, "e05777ef3d989ace7d2abfba452bfded54801dbd5c66e91c0c2ef00479d85572", "b7f526e3fd71cf5720961aec", "15d93a96d0e6c5a9", "17bfda03", "f4710e51", "b957c6a37b6a4c94996c002186d63b2b", true),
            (12, 32, "1a4c4f39abe890e62345c947bcf7de7c2e33bd5ceeda0a0abf0e7ef935ddf3ee", "9447bf85d5b97d8aee0f8e51", "", "c15a593bd0", "f711647ff1", "22b12dc38cb79629f84cdbdc2425c09d", true),
            (13, 32, "800e9a24791700c9609736695ba2a8b99b2d57f1c3bfb61ed49db1c6c5219583", "3dbe876bd880ec8ea2017043", "96224835610b782b", "a7bfd041e3", "d171f046ea", "d179b1b9c4184378df009019dbb8c249", true),
            (14, 32, "208c2c376c9430433db20e1a6b7ba817f8ffbfa6827f26759ccede42e591d3ec", "27fb58ec6a21e84696cb8830", "", "af104b5ccd0e", "9351b1b1b082", "560785509f60f26b681933d9cdbfd29f", true),
            (15, 32, "2eb168e53b07ab04355ea792fe11a6be2ce9c39cfe15a997076b1e38c17ad620", "b5965470c383fd29fe7eaee7", "6d52feb2509f7fbf", "6fdf2927e169", "41abff7b71cc", "9b5174297c03cf8902d1f706fd008902", true),
            (16, 32, "55568158d3a6483f1f7021eab69b703f614251cadc1af5d34a374fdbfc5adac7", "3c4e654d663fa4596dc55bb7", "", "ab85e9c1571731", "5dfe3440dbb3c3", "ed7a434e2602d394281e0afa9fb7aa42", true),
            (17, 32, "e3c09e7fab1aefb516da6a33022a1dd4eb272c80d540c5da52a730f34d840d7f", "58389375c69ee398de948396", "84e46be8c0919053", "4ee5cda20d4290", "4bd47212941ce3", "185f1408ee7fbf18f5abad6e2253a1ba", true),
            (18, 32, "51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152", "4f07afedfdc3b6c2361823d3", "", "be3308f72a2c6aed", "8e9439a56eeec817", "fbe8a6ed8fabb1937539dd6c00e90021", true),
            (19, 32, "1131c1418577a054de7a4ac551950f1a053f9ae46e5b75fe4abd5608d7cddadd", "b4ea666ee119563366484a78", "66c0ae70076cb14d", "a4c9c2801b71f7df", "b9b910433af052b0", "4530f51aeee024e0a445a6328fa67a18", true),
            (20, 32, "e1094967f86d893cdfe2e2e6d5c7ee4dfef67da3c9c5d64e6ad7c1577dcb38c5", "8092fc245b3326cddbd1424c", "", "c37aa791ddd6accf91", "d9d897a9c1c5bb9f01", "085a430373058f1a12a0d589fd5be68b", true),
            (21, 32, "236f9baee4f9da15beeca40ff4af7c760f254a64bc3a3d7f4fad557e61b68586", "f1ca81338629587acf9372bf", "8c32f47a386152ec", "d7f26d5252e1765f5b", "8fdb429d47761cbf8e", "8ef647ed334fdebbc2bef80be02884e0", true),
            (22, 32, "4de207a3b70c51e5f23048eed5a5da9bb65e917a69aa93e7c8b4a815cd9724de", "4c15a71dc6791a8c005ad502", "", "f2c54b6b5e490da18659", "700d35adf5100a22a1de", "102d992ffaff599b5bddddeb2dfb399b", true),
            (146, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f5409bb729039d0814ac514054323f44", false),
            (147, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f6409bb729039d0814ac514054323f44", false),
            (148, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "74409bb729039d0814ac514054323f44", false),
            (149, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f4419bb729039d0814ac514054323f44", false),
            (150, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f4409b3729039d0814ac514054323f44", false),
            (151, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f4409bb728039d0814ac514054323f44", false),
            (152, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f4409bb72b039d0814ac514054323f44", false),
            (153, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f4409bb729039d8814ac514054323f44", false),
            (154, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f4409bb729039d0815ac514054323f44", false),
            (155, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f4409bb729039d08148c514054323f44", false),
            (156, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f4409bb729039d0814ac504054323f44", false),
            (157, 32, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "000102030405060708090a0b", "000102", "", "", "f4409bb729039d0814ac514055323f44", false),
    ];

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    [Fact]
    public void WycheproofAesGcm_VectorsPass()
    {
        if (!Aead.AesGcmSupported)
        {
            return;
        }

        foreach (var row in AesGcmRows)
        {
            using var aead = Aead.CreateAesGcm(Hex(row.Key));
            byte[] msg = Hex(row.Msg);
            byte[] ct = Hex(row.Ct);
            byte[] tag = Hex(row.Tag);
            byte[] wire = new byte[ct.Length + tag.Length];
            ct.CopyTo(wire, 0);
            tag.CopyTo(wire, ct.Length);

            byte[] opened = new byte[msg.Length];
            bool openedOk = aead.TryOpen(Hex(row.Iv), Hex(row.Aad), wire, opened);
            Assert.True(openedOk == row.ExpectOpen, $"tcId={row.Id} open");

            if (row.ExpectOpen)
            {
                Assert.True(opened.AsSpan().SequenceEqual(msg), $"tcId={row.Id} plaintext");
                byte[] resealed = new byte[wire.Length];
                aead.Seal(Hex(row.Iv), Hex(row.Aad), msg, resealed);
                Assert.True(resealed.AsSpan().SequenceEqual(wire), $"tcId={row.Id} seal determinism");
            }
        }
    }

    [Fact]
    public void WycheproofChaCha20Poly1305_VectorsPass()
    {
        if (!Aead.ChaCha20Poly1305Supported)
        {
            return;
        }

        foreach (var row in ChaChaRows)
        {
            using var aead = Aead.CreateChaCha20Poly1305(Hex(row.Key));
            byte[] msg = Hex(row.Msg);
            byte[] ct = Hex(row.Ct);
            byte[] tag = Hex(row.Tag);
            byte[] wire = new byte[ct.Length + tag.Length];
            ct.CopyTo(wire, 0);
            tag.CopyTo(wire, ct.Length);

            byte[] opened = new byte[msg.Length];
            bool openedOk = aead.TryOpen(Hex(row.Iv), Hex(row.Aad), wire, opened);
            Assert.True(openedOk == row.ExpectOpen, $"tcId={row.Id} open");

            if (row.ExpectOpen)
            {
                Assert.True(opened.AsSpan().SequenceEqual(msg), $"tcId={row.Id} plaintext");
                byte[] resealed = new byte[wire.Length];
                aead.Seal(Hex(row.Iv), Hex(row.Aad), msg, resealed);
                Assert.True(resealed.AsSpan().SequenceEqual(wire), $"tcId={row.Id} seal determinism");
            }
        }
    }

    [Fact]
    public void ChaCha20Poly1305_DifferentialAgainstBouncyCastle()
    {
        var rng = new Random(2026);
        for (int i = 0; i < 40; i++)
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            byte[] aad = new byte[rng.Next(0, 40)];
            byte[] plaintext = new byte[rng.Next(0, 400)];
            rng.NextBytes(key);
            rng.NextBytes(nonce);
            rng.NextBytes(aad);
            rng.NextBytes(plaintext);

            var bc = new BcChaChaPoly();
            bc.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce, aad));
            byte[] bcOutput = new byte[plaintext.Length + 16];
            int n = bc.ProcessBytes(plaintext, 0, plaintext.Length, bcOutput, 0);
            bc.DoFinal(bcOutput, n);

            using var aead = Aead.CreateChaCha20Poly1305(key);
            byte[] wire = new byte[plaintext.Length + 16];
            aead.Seal(nonce, aad, plaintext, wire);
            Assert.True(wire.AsSpan().SequenceEqual(bcOutput), $"case {i} seal");

            byte[] opened = new byte[plaintext.Length];
            Assert.True(aead.TryOpen(nonce, aad, wire, opened));
            Assert.True(opened.AsSpan().SequenceEqual(plaintext), $"case {i} open");
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TamperedWire_IsRejectedWithoutThrowing(bool useAesGcm)
    {
        if (useAesGcm && !Aead.AesGcmSupported) return;
        if (!useAesGcm && !Aead.ChaCha20Poly1305Supported) return;
        using var aead = useAesGcm
            ? Aead.CreateAesGcm("0123456789abcdef0123456789abcdef"u8)
            : Aead.CreateChaCha20Poly1305("0123456789abcdef0123456789abcdef0123456789abcdef"u8[..32]);
        byte[] nonce = "0123456789ab"u8.ToArray();
        byte[] plaintext = "authenticated secret payload"u8.ToArray();
        byte[] wire = new byte[plaintext.Length + 16];
        aead.Seal(nonce, [], plaintext, wire);

        byte[] opened = new byte[plaintext.Length];
        Assert.True(aead.TryOpen(nonce, [], wire, opened));

        for (int bit = 0; bit < wire.Length * 8; bit++)
        {
            wire[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.False(aead.TryOpen(nonce, [], wire, opened), $"bit {bit} must reject");
            wire[bit / 8] ^= (byte)(1 << (bit % 8));
        }

        Assert.False(aead.TryOpen("ffffffffffff"u8, [], wire, opened));
        Assert.False(aead.TryOpen(nonce, "x"u8, wire, opened));
        Assert.True(aead.TryOpen(nonce, [], wire, opened));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PerOpCost_IsConstant_IndependentOfPayloadSize(bool useAesGcm)
    {

        if (useAesGcm && !Aead.AesGcmSupported) return;
        if (!useAesGcm && !Aead.ChaCha20Poly1305Supported) return;
        using var aead = useAesGcm
            ? Aead.CreateAesGcm("0123456789abcdef0123456789abcdef"u8)
            : Aead.CreateChaCha20Poly1305("0123456789abcdef0123456789abcdef0123456789abcdef"u8[..32]);
        byte[] nonce = new byte[12];

        long smallPayloadCost = Measure(aead, nonce, 64);
        long largePayloadCost = Measure(aead, nonce, 100 * 1024);
        Assert.True(largePayloadCost <= smallPayloadCost + 4096,
            $"per-op cost grew with payload: small={smallPayloadCost} large={largePayloadCost}");

        static long Measure(Aead aead, byte[] nonce, int payloadSize)
        {
            byte[] plaintext = RandomNumberGenerator.GetBytes(payloadSize);
            byte[] wire = new byte[plaintext.Length + 16];
            byte[] opened = new byte[plaintext.Length];
            aead.Seal(nonce, [], plaintext, wire);
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 50; i++)
            {
                aead.Seal(nonce, [], plaintext, wire);
                if (!aead.TryOpen(nonce, [], wire, opened))
                {
                    throw new InvalidOperationException("round trip broke");
                }
            }

            return (GC.GetAllocatedBytesForCurrentThread() - before) / 50;
        }
    }

    [Fact]
    public void MalformedInputs_TotalBehavior()
    {
        using var aead = Aead.CreateChaCha20Poly1305("0123456789abcdef0123456789abcdef0123456789abcdef"u8[..32]);
        byte[] wire = new byte[50];
        byte[] outBuf = new byte[50];
        Assert.False(aead.TryOpen(new byte[11], [], wire, outBuf));
        Assert.False(aead.TryOpen(new byte[12], [], wire[..15], outBuf));
        Assert.False(aead.TryOpen(new byte[12], [], Array.Empty<byte>(), outBuf));
        Assert.Throws<ArgumentException>(() => aead.Seal(new byte[11], [], wire, outBuf));
        Assert.Throws<ArgumentException>(() => aead.Seal(new byte[12], [], wire, outBuf[..30]));
        Assert.Throws<ArgumentException>(() => Aead.CreateChaCha20Poly1305("short"u8));
        Assert.Throws<ArgumentException>(() => Aead.CreateAesGcm("0123456789abcde"u8[..13]));
    }
}
