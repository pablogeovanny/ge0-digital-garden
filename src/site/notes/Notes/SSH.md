---
{"dg-publish":true,"permalink":"/notes/ssh/"}
---

- **S**ecure **S**hell
- Default port **22**
- Cryptographic remote access **protocol**
- We will need to confirm the fingerprint of the SSH server’s public key to avoid [[MITM attack\|MITM attack]]
# Username and password Authentication
```shell
ssh bandit0@bandit.labs.overthewire.org -p 2220
ssh bandit0@bandit.labs.overthewire.org -p 2220 -oHostKeyAlgorithms=+ssh-rsa
```

```shell
sshpass -p 'password' ssh bandit0@bandit.labs.overthewire.org -p 2220
```
# RSA keys Authentication
- Data **encrypted** with the **private key** can be **decrypted** with the **public key,** and vice versa.
- tends to be **slower** and uses **larger keys**
## Enable service daemon
```sh
sudo systemctl start sshd
```
## Create keys
Create pair of keys RSA keys in `/home/USER/.ssh
```shell
ssh-keygen
```
`id_rsa` (private) (`400` permissions required to remote connection)
`id_rsa.pub` (public)
## Connect from M2 to M1 without password
<style> .container {font-family: sans-serif; text-align: center;} .button-wrapper button {z-index: 1;height: 40px; width: 100px; margin: 10px;padding: 5px;} .excalidraw .App-menu_top .buttonList { display: flex;} .excalidraw-wrapper { height: 800px; margin: 50px; position: relative;} :root[dir="ltr"] .excalidraw .layer-ui__wrapper .zen-mode-transition.App-menu_bottom--transition-left {transform: none;} </style><script src="https://cdn.jsdelivr.net/npm/react@17/umd/react.production.min.js"></script><script src="https://cdn.jsdelivr.net/npm/react-dom@17/umd/react-dom.production.min.js"></script><script type="text/javascript" src="https://cdn.jsdelivr.net/npm/@excalidraw/excalidraw@0/dist/excalidraw.production.min.js"></script><div id="Drawing_2024-11-21_1504.01.excalidraw.md1"></div><script>(function(){const InitialData={"type":"excalidraw","version":2,"source":"https://github.com/zsviczian/obsidian-excalidraw-plugin/releases/tag/2.6.6","elements":[{"type":"ellipse","version":1525,"versionNonce":1395036654,"index":"a0","isDeleted":false,"id":"ItKBEm_z7CVvHtoQ-Zvt4","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-109.49795770010377,"y":-184.65079166059985,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":306718834,"groupIds":["lhru5r4wTwnza6bvzq2Aj"],"frameId":null,"roundness":null,"boundElements":[{"id":"oSynytzaPcs38r0tsKCU6","type":"arrow"}],"updated":1732212752484,"link":null,"locked":false},{"type":"line","version":2421,"versionNonce":582494702,"index":"a1","isDeleted":false,"id":"s2UNtRHYJJrQQQG3qK8tx","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-104.97288084410474,"y":-139.3107040430938,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":1070484018,"groupIds":["wMChwub_GKobYcKfRdVI_","p7FnL7R4Ja1Pe959PYInD","eVfkMiCGQOX3UaViEQ76Y","GcVBTSP8MA4MaQNdVAtMp","jiKO8JUj-LRuGerhUzsG-","lhru5r4wTwnza6bvzq2Aj"],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212284740,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":1988,"versionNonce":1782103086,"index":"a2","isDeleted":false,"id":"0mReoIJAb9nkPm2DJSf5P","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-104.00617415883306,"y":-139.01057774065308,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":598356978,"groupIds":["I1WrksnZh2_BejW7utqek","6rA1Pm27V1RMZzFuK0hLe","TeKd-LG4u5Na7R_Yw4g8q","GcVBTSP8MA4MaQNdVAtMp","jiKO8JUj-LRuGerhUzsG-","lhru5r4wTwnza6bvzq2Aj"],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212284740,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":1840,"versionNonce":275580526,"index":"a3","isDeleted":false,"id":"kSZBBkm52meD2319th-b_","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-64.49158608861643,"y":-109.92763594819476,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":2145576370,"groupIds":["DsfjYGx0N0es021Il5SYO","h4Grl4yp8dVntohCZox_1","cdiLX2ThOL-GZRiJL3mda","GcVBTSP8MA4MaQNdVAtMp","jiKO8JUj-LRuGerhUzsG-","lhru5r4wTwnza6bvzq2Aj"],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212284740,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1350,"versionNonce":1981679790,"index":"a4","isDeleted":false,"id":"ZkkRwVNw86T2Zk-CPaGQG","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-88.00933380468376,"y":-180.17186042004204,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":1033854834,"groupIds":["xHoSXoO6ZihMJxdDFjShT","jiKO8JUj-LRuGerhUzsG-","lhru5r4wTwnza6bvzq2Aj"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1732212284741,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2474,"versionNonce":2062861038,"index":"a5","isDeleted":false,"id":"fgPC6nKIcFk9ESvpZPVY1","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-101.40451389341132,"y":-154.4817898914081,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":153526578,"groupIds":["xHoSXoO6ZihMJxdDFjShT","jiKO8JUj-LRuGerhUzsG-","lhru5r4wTwnza6bvzq2Aj"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1732212284741,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2257,"versionNonce":561657134,"index":"a6","isDeleted":false,"id":"7pW1ioSM2arpFJwLjoSDv","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-98.2226957115933,"y":-154.92716783664142,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":1843374834,"groupIds":["xHoSXoO6ZihMJxdDFjShT","jiKO8JUj-LRuGerhUzsG-","lhru5r4wTwnza6bvzq2Aj"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1732212284741,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":862,"versionNonce":857169774,"index":"a7","isDeleted":false,"id":"3ywiwsyTBHbqTzpkJuDry","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-75.94896577800881,"y":-120.67571003466097,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":1917942962,"groupIds":["jiKO8JUj-LRuGerhUzsG-","lhru5r4wTwnza6bvzq2Aj"],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212284741,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"text","version":167,"versionNonce":31381038,"index":"a8","isDeleted":false,"id":"qebDusBa","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-116.89902473961841,"y":-95.2727163555819,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":96.39993286132812,"height":25,"seed":874714738,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[{"id":"oSynytzaPcs38r0tsKCU6","type":"arrow"}],"updated":1732212787301,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 2","rawText":"Machine 2","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 2","autoResize":true,"lineHeight":1.25},{"type":"ellipse","version":1709,"versionNonce":1883862254,"index":"a9","isDeleted":false,"id":"SAymI9jPVsQP1JSKW6x5G","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":58.70203924813842,"y":-180.3252335210508,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":68909106,"groupIds":["75dezpfozPOgNLt9FAta5"],"frameId":null,"roundness":null,"boundElements":[{"id":"oSynytzaPcs38r0tsKCU6","type":"arrow"}],"updated":1732212794675,"link":null,"locked":false},{"type":"line","version":2606,"versionNonce":1550291310,"index":"aA","isDeleted":false,"id":"z5PeUEplvZZNzOE7z2grb","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":63.22711610413745,"y":-134.98514590354475,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":35758578,"groupIds":["ieC33kT809B4YlqA3neq9","tC_NI2X452nC51JMrH_mm","K7m98T-yq3QiCZSEc6RpA","276Ri-J6ueYwYRqSqG2LU","hCgVjzVe8U03VxwlIBpsi","75dezpfozPOgNLt9FAta5"],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212794675,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":2173,"versionNonce":412038062,"index":"aB","isDeleted":false,"id":"PD6pC9pWQjQBGaif70O40","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":64.19382278940913,"y":-134.68501960110402,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":960271282,"groupIds":["Ynie7ncGO1qLKPTdugN-S","66zUEqc8IhDJ7s2wRb5x4","eQri5V0a3Z2eAUx7A3DiH","276Ri-J6ueYwYRqSqG2LU","hCgVjzVe8U03VxwlIBpsi","75dezpfozPOgNLt9FAta5"],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212794675,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":2025,"versionNonce":738758126,"index":"aC","isDeleted":false,"id":"EG-c1qm1NswZwPLg9IpQT","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":103.70841085962576,"y":-105.6020778086457,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":999509362,"groupIds":["Y5xTZ8AncMi-mpYTVqZWp","2s4V3o6vE_Bo9oK5spz9D","KuTbYwxsfQcn3sJHesZo5","276Ri-J6ueYwYRqSqG2LU","hCgVjzVe8U03VxwlIBpsi","75dezpfozPOgNLt9FAta5"],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212794675,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1535,"versionNonce":870096942,"index":"aD","isDeleted":false,"id":"mq3JWy13Zd5egTg5h2s4B","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":80.19066314355842,"y":-175.84630228049298,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":1047318322,"groupIds":["RyJfpob8q0FPet3-e8HPD","hCgVjzVe8U03VxwlIBpsi","75dezpfozPOgNLt9FAta5"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1732212794675,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2659,"versionNonce":1140091502,"index":"aE","isDeleted":false,"id":"CvcmvnrdFbOBmRKZz5GGP","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":66.79548305483087,"y":-150.15623175185905,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":909121778,"groupIds":["RyJfpob8q0FPet3-e8HPD","hCgVjzVe8U03VxwlIBpsi","75dezpfozPOgNLt9FAta5"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1732212794675,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2442,"versionNonce":186182830,"index":"aF","isDeleted":false,"id":"cYNUlHpn44UZyR_mO4tvy","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":69.97730123664888,"y":-150.60160969709236,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":1919167154,"groupIds":["RyJfpob8q0FPet3-e8HPD","hCgVjzVe8U03VxwlIBpsi","75dezpfozPOgNLt9FAta5"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1732212794675,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":1047,"versionNonce":1995646702,"index":"aG","isDeleted":false,"id":"s74IW64fl1AdMxiYaE70P","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":92.25103117023338,"y":-116.3501518951119,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":967836786,"groupIds":["hCgVjzVe8U03VxwlIBpsi","75dezpfozPOgNLt9FAta5"],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212794675,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"text","version":72,"versionNonce":1360403950,"index":"aH","isDeleted":false,"id":"Lc21CA8T","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":37.06508255004883,"y":-92.11845000066594,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":90.93992614746094,"height":25,"seed":1708828210,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212798779,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 1","rawText":"Machine 1","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 1","autoResize":true,"lineHeight":1.25},{"type":"arrow","version":786,"versionNonce":761833262,"index":"aI","isDeleted":false,"id":"oSynytzaPcs38r0tsKCU6","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-41.42885476976927,"y":-140.6120687891686,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":92.49445677454693,"height":4.485992528311243,"seed":2144014322,"groupIds":[],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1732212794675,"link":null,"locked":false,"startBinding":{"elementId":"ItKBEm_z7CVvHtoQ-Zvt4","focus":0.1685807061962093,"gap":5.132947741453421,"fixedPoint":null},"endBinding":{"elementId":"SAymI9jPVsQP1JSKW6x5G","focus":0.12831485742904392,"gap":7.720678574057114,"fixedPoint":null},"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":"arrow","points":[[0,0],[92.49445677454693,-4.485992528311243]],"elbowed":false},{"type":"text","version":217,"versionNonce":1957857010,"index":"aJ","isDeleted":false,"id":"MDn33M1R","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-115.53493881225586,"y":-67.31849272527532,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":87.63990783691406,"height":25,"seed":1535656370,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212284742,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Attacker","rawText":"Attacker","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Attacker","autoResize":true,"lineHeight":1.25},{"type":"text","version":313,"versionNonce":568869106,"index":"aL","isDeleted":false,"id":"bPptaqkV","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":47.79830318043847,"y":-66.06804044370966,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":66.99992370605469,"height":25,"seed":990774770,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1732212804827,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Target","rawText":"Target","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Target","autoResize":true,"lineHeight":1.25},{"id":"JAoUWDdP","type":"text","x":-45.83498001098633,"y":-187.0190164299981,"width":88.83990478515625,"height":25,"angle":0,"strokeColor":"#1e1e1e","backgroundColor":"transparent","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"groupIds":[],"frameId":null,"index":"aK","roundness":null,"seed":876166002,"version":138,"versionNonce":1513043954,"isDeleted":true,"boundElements":[],"updated":1732212814196,"link":null,"locked":false,"text":"Session 1","rawText":"Session 1","fontSize":20,"fontFamily":5,"textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Session 1","autoResize":true,"lineHeight":1.25}],"appState":{"theme":"dark","viewBackgroundColor":"#ffffff","currentItemStrokeColor":"#1e1e1e","currentItemBackgroundColor":"transparent","currentItemFillStyle":"solid","currentItemStrokeWidth":2,"currentItemStrokeStyle":"solid","currentItemRoughness":1,"currentItemOpacity":100,"currentItemFontFamily":5,"currentItemFontSize":20,"currentItemTextAlign":"left","currentItemStartArrowhead":null,"currentItemEndArrowhead":"arrow","currentItemArrowType":"round","scrollX":208.54062273120255,"scrollY":272.41448507551956,"zoom":{"value":2.313857},"currentItemRoundness":"round","gridSize":20,"gridStep":5,"gridModeEnabled":false,"gridColor":{"Bold":"rgba(217, 217, 217, 0.5)","Regular":"rgba(230, 230, 230, 0.5)"},"currentStrokeOptions":null,"frameRendering":{"enabled":true,"clip":true,"name":true,"outline":true},"objectsSnapModeEnabled":false,"activeTool":{"type":"selection","customType":null,"locked":false,"lastActiveTool":null}},"files":{}};InitialData.scrollToContent=true;App=()=>{const e=React.useRef(null),t=React.useRef(null),[n,i]=React.useState({width:void 0,height:void 0});return React.useEffect(()=>{i({width:t.current.getBoundingClientRect().width,height:t.current.getBoundingClientRect().height});const e=()=>{i({width:t.current.getBoundingClientRect().width,height:t.current.getBoundingClientRect().height})};return window.addEventListener("resize",e),()=>window.removeEventListener("resize",e)},[t]),React.createElement(React.Fragment,null,React.createElement("div",{className:"excalidraw-wrapper",ref:t},React.createElement(ExcalidrawLib.Excalidraw,{ref:e,width:n.width,height:n.height,initialData:InitialData,viewModeEnabled:!0,zenModeEnabled:!0,gridModeEnabled:!1})))},excalidrawWrapper=document.getElementById("Drawing_2024-11-21_1504.01.excalidraw.md1");ReactDOM.render(React.createElement(App),excalidrawWrapper);})();</script>
1### Method 1
 The **public key** (`id_rsa.pub`) of **computer 2** has to be in the file `authorized_keys` in the **computer 1**
 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

# 400

</div>



==⚠  Switch to EXCALIDRAW VIEW in the MORE OPTIONS menu of this document. ⚠== You can decompress Drawing data with the command palette: 'Decompress current Excalidraw file'. For more info check in plugin settings under 'Saving'


# Excalidraw Data
## Text Elements
Machine 2 
Machine 1 
Attacker 
Target 
id_rsa.pub 
authorized_keys 
Copy 


</div></div>

The process to do this depend on some factors but If the `authorized_keys` file doesn't exist, we can simply copy the entire `id_rsa.pub` and change the name, but if the `authorized_keys` exists could content another authorized keys that we shouldn't delete. In this case we could add our key in the bottom of the `authorized_keys` like below:

 1. On the **computer 2**
 **Copy the content** of the file `/home/USER/.ssh/id_rsa.pub`
```sh
cat /home/USER/.ssh/id_rsa.pub
```
![Pasted image 20241001192909.png](/img/user/attachments/Pasted%20image%2020241001192909.png)
Copy to the clipboard

2. On the **computer 1**
Using `echo` paste the code and add or replace the `authorized_keys`
```shell
echo "ssh-rsa AAAA......gv7v......y2w/oJ0= kali@kali" >> authorized_keys
```
E.g. This is the new `authorized_keys`of the **computer 1**
![Pasted image 20241002070248.png](/img/user/attachments/Pasted%20image%2020241002070248.png)

3. On the **computer 2**
All is ready, now to **connect** without password execute:
```shell
ssh USER_OF_COMPUTER_1@IP_COF_COMPUTER_1
```
### Method 2
**Automated** version of the **method 1** but we **need** to introduce the **password** of the computer 1 **at least once**.
1. On the **computer 2**
```shell
ssh-copy-id -i ~/.ssh/id_rsa.pub COMPUTER_1_USERNAME@COMPUTER_1_IP
```
After this our `id_rsa.pub` will copy on `authorized_keys` of the **computer 1**.
### Method 3
1. Set the **public key of comp1** like "authorized_keys" on its machine (Could not work depending on configuration)
   To **let to** any **connect to comp1** if the **computer2** has the private key of comp1.
```shell
cp id_rsa.pub authorized_keys
```
2. Copy the private key (`id_rsa`) from C1 to C2
3. From C2 connect using that private key file of C1 (`id_rsa`) (the permission should be `600`)
```shell
ssh -i id_rsa user@ipaddres
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.10.250.21
```
# Port forwarding
`80` port from a victim machine which we don't have access will be available in our machine on `127.0.0.1:33`
```shell
ssh user@"VICTIM_IP" -L 80:127.0.0.1:33
```
# Transfer files 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Secure Copy Protocol
- **Transferring Files From Your Host**
- MITM
Secure copy, or SCP, is just that -- a means of securely copying files. Unlike the regular cp command, this command allows you to transfer files between two computers using the SSH protocol to provide both authentication and encryption.

Working on a model of SOURCE and DESTINATION, SCP allows you to:

- Copy files & directories from your current system to a remote system
- Copy files & directories from a remote system to your current system

## Send a file
Send file1.txt from my machine to the target machine with the name file2.txt
```shell
scp file1.txt <target_username>@<target_IP>:/home/ubuntu/file2.txt
```
## Download a file
Get the documents.txt from the target machine to my machine. (To my current directory `.`)
```shell
scp <target_username>@<target_IP>:/home/ubuntu/documents.txt .
```
Change the name to notes.txt
```shell
scp <target_username>@<target_IP>:/home/ubuntu/documents.txt notes.txt
```
Examples to get all files from a folder
```shell
scp <target_username>@<target_IP>:/home/ubuntu/* .
```
```shell
scp <target_username>@<target_IP>:/home/ubuntu/* ~
```




</div></div>

# Math
- The key variables that you need to know about for RSA in CTFs are p, q, m, n, e, d, and c.
- “p” and “q” are large prime numbers, “n” is the product of p and q.
- The public key is n and e, the private key is n and d.
- “m” is used to represent the message (in plaintext) and “c” represents the ciphertext (encrypted text).
- https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/

# Tools RSA CTFs
https://github.com/Ganapati/RsaCtfTool
https://github.com/ius/rsatool
# Errors
- If you get an error saying `Unable to negotiate with <IP> port 22: no matching how to key type found. Their offer: ssh-rsa, ssh-dss` 
- this is because OpenSSH have deprecated ssh-rsa. 
- Add `-oHostKeyAlgorithms=+ssh-rsa` to your command to connect.
# Enumeration
Get version and search in [launchpad](https://launchpad.net/ubuntu).
```sh
sudo nmap -sCV -p22 127.0.0.1
```
PORT   STATE SERVICE VERSION
`22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)`
https://launchpad.net/ubuntu
OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
## Using Metasploit 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## [[Notes/SSH\|SSH]] Enum
```shell
auxiliary/scanner/ssh/ssh_version
auxiliary/scanner/ssh/ssh_login # Brute force
```

</div></div>

# Exploitation
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

# John The Ripper

</div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py
```sh
wget https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py
```
Note that if you don't have ssh2john installed, you can use ssh2john.py, which is located in the /opt/john/ssh2john.py. If you're doing this, replace the `ssh2john` command with `python3 /opt/ssh2john.py` or on Kali, `python /usr/share/john/ssh2john.py`.
```sh
ssh2john [id_rsa private key file] > [output file]
```

ssh2john - Invokes the ssh2john tool  

`[id_rsa private key file]` - The path to the id_rsa file you wish to get the hash of

`>` - This is the output director, we're using this to send the output from this file to the...  

`[output file]` - This is the file that will store the output from

**Example Usage**
ssh2john id_rsa > id_rsa_hash.txt

**Cracking**

``` bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
```



</div></div>


</div></div>

## Exploit `libssh`
- `libssh` V.0.6.0 - 0.8-0 is vulnerable to an authentication bypass vulnerability in the `libssh` server code that can be exploited to execute commands on the target server.

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## [[Notes/SSH\|SSH]] Exploitation
```shell
use auxiliary/scanner/ssh/libssh_auth_bypass
set SPAWN_PTY true
run
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

# Hardening SSH

</div>


- In the admin shell, go to the `/etc/ssh/sshd_config` file and edit it using your favourite text editor (remember to use sudo). 
- Find the line that says `#PasswordAuthentication yes` and change it to `PasswordAuthentication no` (remove the # sign and change yes to no).

- Next, find the line that says `Include /etc/ssh/sshd_config.d/*.conf` and change it to `#Include /etc/ssh/sshd_config.d/*.conf` (add a # sign at the beginning). 
- Save the file, then enter the command `sudo systemctl restart ssh`.

</div></div>



