

import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
    const apiUrl = 'http://localhost:8061/create-invitation';
    const response = await fetch(apiUrl);
    const data = await response.json();
    console.log(data);

    return NextResponse.json(data);
}
