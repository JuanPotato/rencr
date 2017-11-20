extern crate byteorder;
extern crate itertools;

use byteorder::{LittleEndian, ByteOrder};
use itertools::multizip;

macro_rules! add {
    ($a:expr, $b:expr) => {
        $a = $a.wrapping_add($b);
    }
}

macro_rules! xor {
    ($a:expr, $b:expr) => {
        $a ^= $b;
    }
}

macro_rules! shift {
    ($i:expr, $n:expr) => {
        $i = $i.rotate_left($n);
    }
}


pub fn encrypt(key: &[u8], nonce: &[u8], mut block_count: u32, input: &[u8], output: &mut [u8]) {
    // key must be 256 bits (8 * 32)
    // nonce must be 96 bits (3 * 32)
    // block count must be 32 bits
    assert_eq!(key.len(), 32);
    assert_eq!(nonce.len(), 12);
    assert_eq!(input.len(), output.len());

    let mut key_stream = [0u8; 64];

    for (in_block, mut out_block) in input.chunks(64).zip(output.chunks_mut(64)) {
        chacha_round(&key, &nonce, block_count, &mut key_stream);

        xor_bytes(&mut out_block, &key_stream, &in_block);

        block_count += 1;
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    add!(state[a], state[b]);
    xor!(state[d], state[a]);
    shift!(state[d], 16);

    add!(state[c], state[d]);
    xor!(state[b], state[c]);
    shift!(state[b], 12);

    add!(state[a], state[b]);
    xor!(state[d], state[a]);
    shift!(state[d], 8);

    add!(state[c], state[d]);
    xor!(state[b], state[c]);
    shift!(state[b], 7);
}

fn inner_round(mut state: &mut [u32; 16]) {
    quarter_round(&mut state, 0, 4, 8, 12);
    quarter_round(&mut state, 1, 5, 9, 13);
    quarter_round(&mut state, 2, 6, 10, 14);
    quarter_round(&mut state, 3, 7, 11, 15);
    quarter_round(&mut state, 0, 5, 10, 15);
    quarter_round(&mut state, 1, 6, 11, 12);
    quarter_round(&mut state, 2, 7, 8, 13);
    quarter_round(&mut state, 3, 4, 9, 14);
}

fn chacha_round(key: &[u8], nonce: &[u8], block_count: u32, mut key_stream: &mut [u8]) {
    let mut state: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // constants
        0, 0, 0, 0, 0, 0, 0, 0, // key
        block_count, // counter
        0, 0, 0, // nonce
    ];

    LittleEndian::read_u32_into(key, &mut state[4..12]);
    LittleEndian::read_u32_into(nonce, &mut state[13..16]);

    let working_state = state.clone();

    for _ in 0..10 {
        inner_round(&mut state);
    }

    add_states(&mut state, &working_state);

    LittleEndian::write_u32_into(&state, &mut key_stream);
}

fn add_states(a: &mut [u32; 16], b: &[u32; 16]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 = b1.wrapping_add(*b2);
    }
}

fn xor_bytes(a: &mut [u8], b: &[u8], c: &[u8]) {
    for (aa, bb, cc) in multizip((a.iter_mut(), b.iter(), c.iter())) {
        *aa = bb ^ cc;
    }
}

