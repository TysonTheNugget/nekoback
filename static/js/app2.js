const attributeMapping = {
  'P': {atk: 10, def: 3, trait: 'fury'},
  'Q': {atk: 7, def: 6, trait: 'ghost'},
  'R': {atk: 6, def: 6, trait: 'LeftRight'},
  'S': {atk: 9, def: 3, trait: 'LoveStory'},
  'T': {atk: 11, def: 1, trait: 'mecha'},
  'V': {atk: 1, def: 13, trait: 'rip'},
  'W': {atk: 7, def: 4, trait: 'squad'},
  'X': {atk: 7, def: 5, trait: 'suingcompanies'},
  'Y': {atk: 9, def: 4, trait: 'sword'},
  'Z': {atk: 7, def: 6, trait: 'uzi'},
  'b': {atk: 5, def: 10, trait: 'winged'},
  'oo': {hp: 1000, trait: 'body1'}, 
  'E': {hp:1200, trait: 'body2'},
  'I': {hp:1100, trait: 'body3'},
  'A': {hp:1300, trait: 'body4'},
  'B': {def: 7, trait: 'bit'},
  'C': {atk: 5, trait: 'bitballs'},
  'D': {atk: 2, def: 2, trait: 'bitship'},
  'F': {atk: 6, def: 2, trait: 'bitwarrior'},
  'G': {def: 7, atk: 2, trait: 'ice'},
  'H': {atk: 5, def: 5, trait: 'ipad'},
  'J': {atk: 5, def: 3, trait: 'reaper'},
  'K': {atk: 3, def: 7, trait: 'risingbunny'},
  'L': {def: 11, trait: 'rock'},
  'M': {atk: 8, def: 4, trait: 'tcg'},
  'N': {atk: 11, trait: 'TIA'},
  'U': {speed: 250, trait: 'bunny'},
  'a': {speed: 220, trait: 'content'},
  'e': {speed: 210, trait: 'fang'},
  'ii': {speed: 200, trait: 'maniac2'},
  'o': {speed: 225, trait: 'open'},
  'u': {speed: 215, trait: 'sad'},
  'aa': {speed: 251, trait: 'smirk'},
  'c': {def: 4, atk: 2, trait: 'Bigeyes'},
  'd': {atk: 5, speed: 20, trait: 'bushygreens'},
  'f': {atk: 3, def: 7, trait: 'Deadders'},
  'g': {atk: 7, speed: 10, trait: 'mad'},
  'h': {atk: 11, def: 3, speed: 5, trait: 'Majin'},
  'j': {def: 12, trait: 'serious'},
  'k': {atk: 7, speed: 7, trait: 'sketchy'},
  'y': {speed: 60, trait: 'UI'},
  'ee': {effect: 'AppleVR'},
  'i': {effect: 'BigGlasses'},
  'AA': {effect: 'biggy'},
  '7': {effect: 'BitWarriorHelm'},
  'uu': {effect: 'Blueomb'},
  '@': {def: 10, atk: 10, effect: 'BlueSunglass'},
  '3': {atk: 25,hp: 280, effect: 'Glasses'},
  '4': {effect: 'Greenomb'},
  'yy': {def: 7, effect: 'karatekid2'},
  '1': {atk: 7, def: 5, speed: 20, effect: 'OOP'},
  'O': {atk: 10, def: 10, effect: 'Redomb'},
  '0': {def: 25, effect: 'X'},
};
let xEffectTriggered = false;
let globalTurnCounter = 0;
function getOrdinalFromInput(ordinalNumber) {
    // Fetch the fight code letter from the form
    const fightCodeLetter = document.getElementById(`ordinal${ordinalNumber}_fightCodeLetter`).value;
    console.log(`Fight code letter for Ordinal ${ordinalNumber}:`, fightCodeLetter);
    
    // Calculate attributes based on the fight code letter
    const calculatedAttributes = calculateAttributesFromCode(fightCodeLetter);
    console.log(`Calculated attributes for Ordinal ${ordinalNumber}:`, calculatedAttributes);
    
    // Log effects after calculatedAttributes is defined
    console.log(`Effects for Ordinal ${ordinalNumber}:`, calculatedAttributes.effects);

    // Construct the ordinal object
    return {
        name: `Ordinal ${ordinalNumber}`,
        hp: calculatedAttributes.hp || 0,  // Use calculated hp, default to 0 if undefined
        atk: calculatedAttributes.atk || 0,  // Use calculated ATK, default to 0 if undefined
        def: calculatedAttributes.def || 0,  // Use calculated DEF, default to 0 if undefined
        speed: calculatedAttributes.speed || 0,  // Use calculated SPEED, default to 0 if undefined
        biggyActivated: false,  // Initialize the biggyActivated flag
        attackCounter: 0,       // Initialize the attackCounter
        karatekid2Activated: false,  // Initialize the karatekid2Activated flag
        bitWarriorHelmHpTriggered: false,  // Initialize the bitWarriorHelmHpTriggered flag
        traits: calculatedAttributes.traits || [],  // Separate traits
        effects: calculatedAttributes.effects || [],  // Separate effects
        bitWarriorAtkTriggered: false,  // Initialize the bitWarriorAtkTriggered flag
        appleVRCounter: 0  // Initialize the appleVRCounter
    };
}



function updateStatsFromObject(ordinalNumber, ordinalObject) {
    document.getElementById(`ordinal${ordinalNumber}_hp`).value = ordinalObject.hp;
    document.getElementById(`ordinal${ordinalNumber}_atk`).value = ordinalObject.atk;
    document.getElementById(`ordinal${ordinalNumber}_def`).value = ordinalObject.def;
    document.getElementById(`ordinal${ordinalNumber}_speed`).value = ordinalObject.speed;
    document.getElementById(`ordinal${ordinalNumber}_effect_display`).value = ordinalObject.effects.join(', ');
}

// Attach the resetBattle function to the "Reset Battle" button

function startBattle() {
    const ordinal1 = getOrdinalFromInput(1);
    const ordinal2 = getOrdinalFromInput(2);

    let activeOrdinal = ordinal1.speed >= ordinal2.speed ? ordinal1 : ordinal2;
    let defendingOrdinal = activeOrdinal === ordinal1 ? ordinal2 : ordinal1;
    let ordinalsAttackedThisTurn = 0;  

    let battleInterval = setInterval(() => {
        logToConsole(`--- Turn ${globalTurnCounter + 1} ---`);
        logToConsole(`${activeOrdinal.name} STATS - HP: ${activeOrdinal.hp}, ATK: ${activeOrdinal.atk}, DEF: ${activeOrdinal.def}`);
        logToConsole(`${defendingOrdinal.name} STATS - HP: ${defendingOrdinal.hp}, ATK: ${defendingOrdinal.atk}, DEF: ${defendingOrdinal.def}`);

        applyEffects(activeOrdinal, defendingOrdinal);
        if (activeOrdinal.effects.includes('BitWarriorHelm')) {
            applyBitWarriorHelmEffect(activeOrdinal);
        }
         if (xEffectTriggered) {
            xEffectTriggered--;
            if (xEffectTriggered === 0) {
                activeOrdinal.atk -= 70;  // Reset the ATK value
            }
        }
       let attacks = getAttackCount(activeOrdinal);
for (let i = 0; i < attacks; i++) {
    console.log(`Attack ${i + 1} of ${attacks}`);
    console.log(`defender.attackCounter before calculateDamage: ${defendingOrdinal.attackCounter}`);  // Debug log
    console.log(`defender.effects before calculateDamage: ${JSON.stringify(defendingOrdinal.effects)}`);
    let damage = calculateDamage(activeOrdinal, defendingOrdinal);
    activeOrdinal.attackCounter = (activeOrdinal.attackCounter || 0) + 1;  // Increment the attack counter of the attacking ordinal - MODIFIED LINE
    defendingOrdinal.hp = Math.max(0, defendingOrdinal.hp - damage);  // Modified line
    if (damage > 0) logToConsole(`${activeOrdinal.name} attacks with ${damage} damage. ${defendingOrdinal.name} now has ${defendingOrdinal.hp} HP left.`);
    if (defendingOrdinal.hp <= 0) {
        clearInterval(battleInterval);
        logToConsole(`${defendingOrdinal.name} is defeated! ${activeOrdinal.name} wins!`);
        return;
    }
}

        ordinalsAttackedThisTurn++;  
        if (ordinalsAttackedThisTurn == 2) {
            globalTurnCounter++;  
            ordinalsAttackedThisTurn = 0;  
        }

        [activeOrdinal, defendingOrdinal] = [defendingOrdinal, activeOrdinal];  

    }, 2000);
}

// Paste this code to replace your existing calculateAttributesFromCode function
function applyBitWarriorHelmEffect(activeOrdinal) {
  // Only increase HP once per battle when it reaches 500
  if (activeOrdinal.hp <= 500 && !activeOrdinal.bitWarriorHelmHpTriggered) {
    activeOrdinal.hp += 300;
    activeOrdinal.bitWarriorHelmHpTriggered = true; // Set the flag to true so it doesn't activate again
    logToConsole(`${activeOrdinal.name} gains 300 HP due to its BitWarriorHelm effect.`);
  }

  // Increase ATK by 20 on turn 5 when paired with bitwarrior
  if ((globalTurnCounter + 1) === 5 && 
         activeOrdinal.traits.includes('bitwarrior') && 
         !activeOrdinal.bitWarriorAtkTriggered) {  // This checks if the effect has been triggered already
        activeOrdinal.atk += 20;
        activeOrdinal.bitWarriorAtkTriggered = true;  // This sets the flag to true so it doesn't activate again
        logToConsole(`${activeOrdinal.name} gains 10 ATK due to its pairing with bitwarrior on turn 5.`);
    }
}
function calculateAttributesFromCode(fightCode) {
    
    console.log("Initial fight code:", fightCode);  // Debugging line

    let attributes = { atk: 0, def: 0, speed: 0, hp: 0, traits: [], effects: [] }; // Initialize the attributes

    // Debugging: print attributeMapping
    console.log("attributeMapping:", attributeMapping);  // Debugging line

    // First, look for multi-character keys
    for (const multiCharKey of ["ii", "oo", "aa", "uu", "yy", "ee", "AA"]) {
        while (fightCode.includes(multiCharKey)) {
            const mappedAttributes = attributeMapping[multiCharKey] || {};
            attributes.atk += (mappedAttributes.atk || 0);
            attributes.def += (mappedAttributes.def || 0);
            attributes.speed += (mappedAttributes.speed || 0);
            attributes.hp += (mappedAttributes.hp || 0);

            // Check for effects and ensure they are treated as an array
            if (mappedAttributes.effect) {
                if (!Array.isArray(mappedAttributes.effect)) {
                    mappedAttributes.effect = [mappedAttributes.effect];
                }
                attributes.effects.push(...mappedAttributes.effect);
            }

            fightCode = fightCode.replace(multiCharKey, '');  // Remove the multiCharKey from fightCode
        }
    }

    // Debugging: check the attributes after multiCharKey mapping
    console.log("Attributes after multiCharKey mapping:", attributes);  // Debugging line

    // Now, proceed with single-character keys
    const chars = fightCode.split(''); // Split the fight code into its individual characters

    for (const char of chars) {
        const mappedAttributes = attributeMapping[char] || {};
        attributes.atk += mappedAttributes.atk || 0;
        attributes.def += mappedAttributes.def || 0;
        attributes.speed += mappedAttributes.speed || 0;
        attributes.hp += mappedAttributes.hp || 0;
        if (mappedAttributes.trait) {
            attributes.traits.push(mappedAttributes.trait);
        }
        if (mappedAttributes.effect) {
            attributes.effects.push(mappedAttributes.effect);
            console.log(`Added effect ${mappedAttributes.effect}`); 
        }
    }

    // Debugging: check the final attributes
    console.log("Final attributes:", attributes);  // Debugging line

    return attributes; 

};


function updateStats(ordinalNumber) {
    const ordinal = getOrdinalFromInput(ordinalNumber);  // Use your existing function to get the stats

    // Update the form fields with the calculated stats
    document.getElementById(`ordinal${ordinalNumber}_hp`).value = ordinal.hp;
    document.getElementById(`ordinal${ordinalNumber}_atk`).value = ordinal.atk;
    document.getElementById(`ordinal${ordinalNumber}_def`).value = ordinal.def;
    document.getElementById(`ordinal${ordinalNumber}_speed`).value = ordinal.speed;

    // Update the effect display
    document.getElementById(`ordinal${ordinalNumber}_effect_display`).value = ordinal.effects.join(', ');
}
function applyEffects(activeOrdinal, defendingOrdinal) {
    console.log("Applying effects...");
    console.log('Before applying effects:', JSON.stringify({ activeOrdinal, defendingOrdinal }));
    if (activeOrdinal.effects.includes("BlueSunglass")) {
        logToConsole(`${activeOrdinal.name} activated BlueSunglass effect.`);
        logToConsole(`BlueSunglass was activated! (Effect: enemy ordinal effect is negated)`);
        defendingOrdinal.effects = [];
        return;
    }

    if (activeOrdinal.effects.includes("X")) {
    if ((globalTurnCounter - 3) % 10 === 0 && globalTurnCounter !== 3) {  // Turn 13, 23, 33, etc.
        activeOrdinal.atk -= 30;  // Decrease ATK by 30
        logToConsole(`${activeOrdinal.name} loses 30 ATK due to X effect ending.`);
    } else if (globalTurnCounter % 10 === 0 && globalTurnCounter !== 0) {  // Turn 10, 20, 30, etc.
        activeOrdinal.atk += 30;  // Increase ATK by 30
        logToConsole(`${activeOrdinal.name} gains 30 ATK due to X effect.`);
    }
}

    if (activeOrdinal.effects.includes("AppleVR") && activeOrdinal.appleVRCounter < 3) {
        activeOrdinal.atk += 10;
        activeOrdinal.appleVRCounter++;
        logToConsole(`${activeOrdinal.name} gains 20 ATK for AppleVR effect.`);
        logToConsole(`AppleVR was activated! (Effect: Gains 10 atk but only for the first 3 turns)`);
    }

    if (activeOrdinal.effects.includes("OOP") && globalTurnCounter === 3) {
        let result = Math.random() < 0.5 ? "heads" : "tails";
        logToConsole(`OOP effect flips a coin: ${result}`);
        if (result === "heads") {
            activeOrdinal.atk += 20;
            logToConsole(`${activeOrdinal.name} gained 20 ATK from OOP effect.`);
            logToConsole(`OOP was activated!`);
        } else {
            activeOrdinal.def -= 10;
            logToConsole(`${activeOrdinal.name} lost 10 DEF from OOP effect.`);
            logToConsole(`OOP was activated but turned out to be detrimental!`);
        }
    }

    if (activeOrdinal.effects.includes("BigGlasses") && !activeOrdinal.bigGlassesActivated) {
    if (defendingOrdinal.atk > activeOrdinal.atk) {
        defendingOrdinal.def -= 15;
        logToConsole(`${defendingOrdinal.name} loses 15 DEF due to ${activeOrdinal.name}'s BigGlasses effect.`);
        logToConsole(`BigGlasses was activated! (Effect: At start of battle if enemy atk is higher decrease their defense by 15. If lower increase this card atk by 7)`);
    } else {
        activeOrdinal.atk += 7;
        logToConsole(`${activeOrdinal.name} gains 7 ATK due to its BigGlasses effect.`);
    }
    activeOrdinal.bigGlassesActivated = true;
}

     if (activeOrdinal.effects.includes("biggy") && !activeOrdinal.biggyActivated) {
        activeOrdinal.def -= 5;
        activeOrdinal.atk += 12;
        activeOrdinal.biggyActivated = true;
        logToConsole(`${activeOrdinal.name} activates biggy effect: -5 DEF and +12 ATK.`);
        logToConsole(`biggy was activated! (Effect: decreases own defense by 5 and increases attack by 12 for the rest of battle)`);
    }

    if (activeOrdinal.effects.includes("Greenomb")) {
        activeOrdinal.atk += 1;
        activeOrdinal.def += 1;
        logToConsole(`${activeOrdinal.name} increases its ATK and DEF by 1 due to its Greenomb effect.`);
        logToConsole(`Greenomb was activated! (Effect: every time this ordinal attacks increase its own atk and def by 1)`);
    }

    if (activeOrdinal.effects.includes("karatekid2") && !activeOrdinal.karatekid2Activated) {
    if (activeOrdinal.hp < 500) {
        activeOrdinal.atk += 55;
        activeOrdinal.karatekid2Activated = true;
        logToConsole(`${activeOrdinal.name} gains 55 ATK because its HP is below 500 due to its karatekid2 effect.`);
        logToConsole(`karatekid2 was activated! (Effect: when hp is below 500 this ordinal gains 55 atk)`);
    } else {
        logToConsole(`karatekid2 effect checked, but ${activeOrdinal.name}'s HP is not below 500.`);
    }
}

    if (defendingOrdinal.effects.includes("Blueomb")) {
    activeOrdinal.atk = Math.max(0, activeOrdinal.atk - 1);  // Modified line
    activeOrdinal.def = Math.max(0, activeOrdinal.def - 1);  // Modified line
    logToConsole(`${activeOrdinal.name} loses 1 ATK and 1 DEF because ${defendingOrdinal.name} has the Blueomb effect.`);
    logToConsole(`Blueomb was activated on the defending Ordinal! (Effect: when attacked enemy loses 1 atk and 1 def)`);
}

    if (activeOrdinal.effects.includes("Redomb") && globalTurnCounter % 4 === 0) {
        logToConsole(`Redomb was activated! (Effect: can attack twice every 4 turns)`);
        console.log('After applying effects:', JSON.stringify({ activeOrdinal, defendingOrdinal }));

    }
}


function calculateDamage(attacker, defender) {
    console.log('Calculating damage:', { attacker, defender });
    let attackValue = attacker.atk;
    console.log(`Initial attackValue: ${attackValue}`);  // Debug log
    console.log(`defender.attackCounter: ${defender.attackCounter}`);  // Debug log
    console.log(`defender.effects: ${JSON.stringify(defender.effects)}`);  // Debug log

  

    console.log(`Final attackValue: ${attackValue}`);  // Debug log
    return Math.max(attackValue - (defender.def * 0.1), 0);
}

function logToConsole(message) {
    const logDiv = document.createElement('div');
    logDiv.innerText = message;
    document.getElementById('consoleLog').appendChild(logDiv);
    const spacer = document.createElement('div');
    spacer.style.height = "5px";
    document.getElementById('consoleLog').appendChild(spacer);
}

// Add this function to your code. Place it anywhere among the other functions.
function getAttackCount(ordinal) {
    if (ordinal.effects.includes("Redomb") && globalTurnCounter % 4 === 0) {
        return 2;
    }
    return 1;
}

function logEffectDefinition(effect) {
    const definitions = {
        "AppleVR": "Gains 10 atk but only for the first 3 turns",
        "BigGlasses": "At start of battle if enemy atk is higher decrease their defense by 15. If lower increase this card atk by 7",
        "Redomb": "Can attack twice every 4 turns",
        "biggy": "Decreases own defense by 5 and increases attack by 12 for the rest of battle",
        "Greenomb": "Every time this ordinal attacks increase its own atk and def by 6",
        'BitWarriorHelm': 'Increase HP by 300 when HP reaches 500. When paired with bitwarrior,        increase the ATK of this card by 20 on turn 5',
        "karatekid2": "When hp is below 50 this ordinal gains 55 atk",
        "Blueomb": "When attacked enemy loses 1 atk and 1 def"
    };
    logToConsole(`Effect Definition: ${definitions[effect]}`);
}

